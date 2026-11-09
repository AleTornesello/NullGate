use nullgate_core::{
    CompileError, HttpScheme, ImportError, MAX_IMPORT_BYTES, MAX_RULE_LINE_BYTES, MAX_RULES,
    NormalizedHost, Rule, RuleSet, UrlError, normalize_authority, normalize_host, normalize_url,
    parse_blocklist,
};

fn rules(input: &str) -> RuleSet {
    let report = parse_blocklist(input);
    assert_eq!(report.fatal_error, None);
    assert!(report.malformed.is_empty(), "{:?}", report.malformed);
    RuleSet::compile(report.accepted.into_iter().map(|entry| entry.rule)).unwrap()
}

fn blocked(set: &RuleSet, input: &str) -> bool {
    set.blocks_url(&normalize_url(input).unwrap())
}

#[test]
fn exact_and_wildcard_domains_follow_specification() {
    for (rule, host, expected) in [
        ("example.com", "example.com", true),
        ("example.com", "www.example.com", false),
        ("example.com", "api.example.com", false),
        ("*.example.com", "www.example.com", true),
        ("*.example.com", "a.b.example.com", true),
        ("*.example.com", "example.com", false),
        ("*.example.com", "otherexample.com", false),
        ("*.example.com", "badexample.com", false),
        ("*.tracking.example.com", "a.b.tracking.example.com", true),
        ("localhost", "localhost", true),
    ] {
        assert_eq!(
            rules(rule).blocks_domain(&normalize_host(host).unwrap()),
            expected,
            "{rule} {host}"
        );
    }
    let set = rules("example.com\n*.example.com");
    assert!(set.blocks_domain(&normalize_host("EXAMPLE.COM.").unwrap()));
    assert!(set.blocks_domain(&normalize_host("a.example.com").unwrap()));
}

#[test]
fn every_url_example_in_specification() {
    for (pattern, blocked_paths, allowed_paths) in [
        (
            "/ads",
            vec!["/ads", "/ads?campaign=summer"],
            vec!["/ads/", "/ads/banner.png", "/adsense"],
        ),
        (
            "/ads/*",
            vec!["/ads", "/ads/", "/ads/banner.png", "/ads/images/banner.png"],
            vec!["/adsense", "/news"],
        ),
        (
            "/*/banner.png",
            vec!["/ads/banner.png", "/a/b/banner.png"],
            vec!["/ads/banner.jpg"],
        ),
        (
            "/ads*",
            vec!["/ads", "/adsense", "/ads/banner.png"],
            vec!["/news"],
        ),
        (
            "/sponsored/*",
            vec!["/sponsored", "/sponsored/story"],
            vec!["/sponsoredness"],
        ),
        ("/*", vec!["/", "/a/b"], vec![]),
        (
            "/a*/ads/*",
            vec!["/ab/ads", "/ab/ads/x"],
            vec!["/ab/adsense"],
        ),
    ] {
        let set = rules(&format!("https://example.com{pattern}"));
        for path in blocked_paths {
            assert!(
                blocked(&set, &format!("https://example.com{path}")),
                "{pattern} {path}"
            );
        }
        for path in allowed_paths {
            assert!(
                !blocked(&set, &format!("https://example.com{path}")),
                "{pattern} {path}"
            );
        }
    }
}

#[test]
fn schemes_hosts_ports_and_queries_are_separate() {
    let set = rules("HTTPS://EXAMPLE.COM.:0443/ads?ignored=1\nhttps://example.com:8443/special");
    for input in [
        "https://example.com/ads",
        "https://example.com:443/ads?x=%ZZ",
        "https://example.com/ads?x=/../news",
    ] {
        assert!(blocked(&set, input));
    }
    for input in [
        "http://example.com/ads",
        "https://www.example.com/ads",
        "https://example.com:8443/ads",
        "https://example.com/special",
    ] {
        assert!(!blocked(&set, input));
    }
    assert!(blocked(&set, "https://example.com:8443/special"));
    let url = normalize_url("HTTP://Example.com").unwrap();
    assert_eq!(url.scheme(), HttpScheme::Http);
    assert_eq!(url.port(), 80);
    assert_eq!(url.path(), "/");
    assert_eq!(url.host(), &normalize_host("example.com").unwrap());
}

#[test]
fn url_rules_never_block_dns_and_only_https_selects_inspection() {
    let set = rules(
        "http://plain.example/ads\nhttps://secure.example:8443/ads\nblocked.example\nhttps://blocked.example/ads",
    );
    for host in ["plain.example", "secure.example", "www.secure.example"] {
        assert!(!set.blocks_domain(&normalize_host(host).unwrap()));
    }
    assert!(!set.requires_inspection(&normalize_host("plain.example").unwrap()));
    assert!(set.requires_inspection(&normalize_host("SECURE.example.").unwrap()));
    assert!(!set.requires_inspection(&normalize_host("www.secure.example").unwrap()));
    assert!(!set.requires_inspection(&normalize_host("blocked.example").unwrap()));
    assert!(blocked(&set, "https://blocked.example:8443/news"));
    assert!(!blocked(&set, "https://secure.example:443/ads"));
    assert!(!blocked(&set, "https://secure.example:8443/news"));
}

#[test]
fn idna_case_and_dot_equivalence_is_shared() {
    for input in [
        "BÜCHER.example.",
        "xn--bcher-kva.example",
        "bücher。example。",
    ] {
        assert_eq!(
            normalize_host(input).unwrap(),
            normalize_host("bücher.example").unwrap()
        );
        assert!(
            rules("*.bücher.example")
                .blocks_domain(&normalize_host(&format!("a.{input}")).unwrap())
        );
    }
    assert!(blocked(
        &rules("https://bücher.example/ads"),
        "https://XN--BCHER-KVA.example./ads"
    ));
    assert_ne!(
        normalize_host("faß.example").unwrap(),
        normalize_host("fass.example").unwrap()
    );
}

#[test]
fn invalid_hosts_are_not_silently_reinterpreted() {
    for input in [
        "",
        ".",
        "example..com",
        "example.com..",
        "_srv.example",
        "-a.example",
        "a-.example",
        "ab--cd.example",
        "xn--.example",
        "example.com/path",
        "a b.example",
        "a\u{00a0}b.example",
        "example.com\n",
        "*.example.com",
        "127.1",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "2130706433",
        "example.123",
        "127.0.0.1.",
        "[::1%25lo]",
        "::1",
    ] {
        assert!(normalize_host(input).is_err(), "{input:?}");
    }
    assert!(normalize_host(&format!("{}.example", "a".repeat(64))).is_err());
    assert!(
        normalize_host(&format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        ))
        .is_err()
    );
}

#[test]
fn ip_urls_are_canonical_but_ip_domain_rules_are_rejected() {
    assert!(matches!(
        normalize_host("127.0.0.1").unwrap(),
        NormalizedHost::Ipv4(_)
    ));
    assert_eq!(
        normalize_host("[2001:0DB8:0:0::1]").unwrap(),
        normalize_host("[2001:db8::1]").unwrap()
    );
    for input in ["127.0.0.1", "[::1]", "*.127.0.0.1"] {
        assert!(Rule::parse(input).is_err());
    }
    let set = rules("https://[2001:db8::1]/ads\nhttp://127.0.0.1/ads");
    assert!(blocked(&set, "https://[2001:0db8::1]:443/ads"));
    assert!(set.requires_inspection(&normalize_host("[2001:db8::1]").unwrap()));
    assert!(!set.blocks_domain(&normalize_host("127.0.0.1").unwrap()));
}

#[test]
fn authority_parsing_supports_connect_without_guessing_ports() {
    for (input, default, host, port) in [
        ("Example.com:0443", None, "example.com", 443),
        ("[2001:db8::1]:8443", None, "[2001:db8::1]", 8443),
        ("example.com", Some(80), "example.com", 80),
    ] {
        let authority = normalize_authority(input, default).unwrap();
        assert_eq!(authority.host(), &normalize_host(host).unwrap());
        assert_eq!(authority.port(), port);
    }
    for input in [
        "example.com",
        "example.com:",
        "example.com:0",
        "example.com:65536",
        "example.com:+443",
        "example.com: 443",
        "example.com:４４３",
        "::1:443",
        "user@example.com:443",
        "example.com:443/x",
        "[::1]junk:443",
        "[::1]:443:80",
    ] {
        assert!(normalize_authority(input, None).is_err(), "{input}");
    }
    assert!(normalize_authority("example.com", Some(0)).is_err());
}

#[test]
fn canonical_paths_preserve_the_chosen_boundaries() {
    for (input, expected) in [
        ("", "/"),
        ("/Ads", "/Ads"),
        ("//ads/", "//ads/"),
        ("/a/../ads", "/ads"),
        ("/a/./ads", "/a/ads"),
        ("/%2e/ads", "/ads"),
        ("/a/%2E%2e/ads", "/ads"),
        ("/../../ads", "/ads"),
        ("/a/..", "/"),
        ("/a/.", "/a/"),
        ("/a//../ads", "/a/ads"),
        ("/a/..//ads", "//ads"),
        ("/%61ds/%7e", "/ads/~"),
        ("/a%2fb", "/a%2Fb"),
        ("/%252f", "/%252f"),
        ("/%3f%23%2a", "/%3F%23%2A"),
        ("/café", "/caf%C3%A9"),
        ("/caf%c3%a9", "/caf%C3%A9"),
    ] {
        assert_eq!(
            normalize_url(&format!("https://example.com{input}"))
                .unwrap()
                .path(),
            expected,
            "{input}"
        );
    }
    let set = rules("https://example.com/ads\nhttps://example.com/a%2Fb\nhttps://example.com/%2A");
    assert!(blocked(&set, "https://example.com/a/../%61ds?x=1"));
    for input in ["/Ads", "/ads/", "//ads", "/a/b", "/something", "/*"] {
        assert!(
            !blocked(&set, &format!("https://example.com{input}")),
            "{input}"
        );
    }
    assert!(blocked(&set, "https://example.com/%2a"));
}

#[test]
fn request_asterisks_do_not_become_patterns() {
    let set = rules("https://example.com/ads");
    assert!(!blocked(&set, "https://example.com/*"));
    assert!(blocked(
        &rules("https://example.com/a**b*"),
        "https://example.com/ab"
    ));
    assert!(blocked(
        &rules("https://example.com/*/../ads"),
        "https://example.com/ads"
    ));
}

#[test]
fn malformed_urls_and_unsupported_formats_report_safe_diagnostics() {
    let inputs = [
        "ftp://example.com/ads",
        "https://*.example.com/ads",
        "https://user:password@example.com/ads",
        "https://exa%6dple.com/ads",
        "https://example.com/ads#fragment",
        "https://example.com/ads?x=1#fragment",
        "https://example.com/a\\b",
        "https://example.com/a b",
        "https://example.com/a?x=has space",
        "https://example.com/%",
        "https://example.com/%GG",
        "https://example.com/%00",
        "https://example.com/%7f",
        "https://example.com/[ab]",
        "https://example.com/a|b",
        "https:///ads",
        "https://example.com:",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://127.1/ads",
        "https://[::1]oops/ads",
        "||example.com^",
        "@@example.com",
        "0.0.0.0 example.com",
        "/ads.*/",
        "example.com/path",
        "example.com # inline",
        "https://example.com\r/ads",
    ];
    let report = parse_blocklist(&inputs.join("\n"));
    assert!(report.accepted.is_empty());
    assert_eq!(report.malformed.len(), inputs.len());
    for (i, diagnostic) in report.malformed.iter().enumerate() {
        assert_eq!(diagnostic.line, i + 1);
        assert!(!diagnostic.code.is_empty());
        assert!(!diagnostic.message.contains("password"));
    }
    assert_eq!(
        normalize_url("https://example.com/#fragment"),
        Err(UrlError::Fragment)
    );
}

#[test]
fn mixed_imports_preserve_line_numbers_duplicates_and_ignored_lines() {
    let report = parse_blocklist(
        "\u{feff}  # heading\r\n\r\n Example.COM. \r\nexample.com\r\nhttps://example.com:443/ads?x=1\r\nHTTPS://EXAMPLE.COM/ads\r\nmalformed rule\r\n\t*.example.com\t\r\n",
    );
    assert_eq!(
        report.accepted.iter().map(|e| e.line).collect::<Vec<_>>(),
        [3, 5, 8]
    );
    assert_eq!(
        report
            .duplicates
            .iter()
            .map(|d| (d.line, d.original_line))
            .collect::<Vec<_>>(),
        [(4, 3), (6, 5)]
    );
    assert_eq!(report.malformed.len(), 1);
    assert_eq!(report.malformed[0].line, 7);
    assert_eq!(report.ignored_lines, 2);
    assert_eq!(parse_blocklist("").ignored_lines, 0);
    assert!(parse_blocklist("").accepted.is_empty());
    assert_eq!(parse_blocklist(" \n\t# x\n").ignored_lines, 2);
    for input in [
        "\u{feff}\u{feff}example.com",
        "\u{00a0}example.com",
        "example.com\r",
    ] {
        assert_eq!(parse_blocklist(input).malformed.len(), 1, "{input:?}");
    }
}

#[test]
fn body_line_and_request_size_limits_are_explicit() {
    let prefix = "https://example.com/";
    let exact = format!("{prefix}{}", "a".repeat(MAX_RULE_LINE_BYTES - prefix.len()));
    assert_eq!(parse_blocklist(&exact).accepted.len(), 1);
    let report = parse_blocklist(&format!("{exact}x\nexample.com"));
    assert_eq!(report.malformed[0].code, "line_too_long");
    assert_eq!(report.accepted[0].line, 2);
    assert_eq!(normalize_url(&format!("{exact}x")), Err(UrlError::TooLong));
    let report = parse_blocklist(&"#".repeat(MAX_IMPORT_BYTES + 1));
    assert_eq!(report.fatal_error, Some(ImportError::BodyTooLarge));
    assert!(report.accepted.is_empty());
    assert_eq!(
        parse_blocklist(&format!("#{}", "a".repeat(MAX_IMPORT_BYTES - 1))).fatal_error,
        None
    );
}

#[test]
fn compilation_deduplicates_without_merging_domain_and_url_rules() {
    let domain = Rule::parse("example.com").unwrap();
    let url = Rule::parse("https://example.com/ads").unwrap();
    let set = RuleSet::compile([domain.clone(), domain, url]).unwrap();
    assert_eq!(set.len(), 2);
    assert!(!set.is_empty());
    assert!(blocked(&set, "http://example.com:8080/news"));
    assert!(RuleSet::compile([]).unwrap().is_empty());
    assert!(
        !RuleSet::compile([])
            .unwrap()
            .blocks_url(&normalize_url("https://example.com/ads").unwrap())
    );
}

#[test]
fn compilation_enforces_unique_policy_capacity() {
    let input = (0..MAX_RULES)
        .map(|i| Rule::parse(&format!("d{i}.example")).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        RuleSet::compile(input.iter().cloned()).unwrap().len(),
        MAX_RULES
    );
    assert_eq!(
        RuleSet::compile(
            input
                .into_iter()
                .chain([Rule::parse("one-more.example").unwrap()])
        )
        .unwrap_err(),
        CompileError::TooManyRules
    );
    let one = Rule::parse("example.com").unwrap();
    assert_eq!(
        RuleSet::compile(std::iter::repeat_n(one, MAX_RULES + 1))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn adversarial_wildcards_are_bounded_and_nonrecursive() {
    let pattern = format!("/{}b", "*a".repeat(1500));
    let set = rules(&format!("https://example.com{pattern}"));
    assert!(!blocked(
        &set,
        &format!("https://example.com/{}c", "a".repeat(3000))
    ));
    assert!(blocked(
        &set,
        &format!("https://example.com/{}b", "a".repeat(3000))
    ));
    let set = rules(&format!("https://example.com/{}b", "*".repeat(4000)));
    assert!(blocked(&set, "https://example.com/ab"));
}

// Independent dynamic-programming oracle, deliberately unlike the production last-star matcher.
fn glob_oracle(pattern: &[u8], path: &[u8]) -> bool {
    let mut rows = vec![vec![false; path.len() + 1]; pattern.len() + 1];
    rows[0][0] = true;
    for (i, byte) in pattern.iter().enumerate() {
        for j in 0..=path.len() {
            rows[i + 1][j] = if *byte == b'*' {
                rows[i][j] || (j > 0 && rows[i + 1][j - 1])
            } else {
                j > 0 && *byte == path[j - 1] && rows[i][j - 1]
            };
        }
    }
    rows[pattern.len()][path.len()]
}

fn words(alphabet: &[u8], max: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut previous = vec![String::new()];
    for _ in 0..max {
        let mut next = Vec::new();
        for prefix in previous {
            for byte in alphabet {
                next.push(format!("{prefix}{}", *byte as char));
            }
        }
        all.extend(next.iter().cloned());
        previous = next;
    }
    all
}

#[test]
fn wildcard_matcher_agrees_with_an_independent_exhaustive_oracle() {
    let paths = words(b"ab/", 4)
        .into_iter()
        .map(|word| format!("/{word}"))
        .collect::<Vec<_>>();
    for word in words(b"ab/*", 4) {
        let pattern = format!("/{word}");
        let set = rules(&format!("https://example.com{pattern}"));
        for path in &paths {
            let expected = glob_oracle(pattern.as_bytes(), path.as_bytes())
                || pattern
                    .strip_suffix("/*")
                    .is_some_and(|parent| glob_oracle(parent.as_bytes(), path.as_bytes()));
            assert_eq!(
                blocked(&set, &format!("https://example.com{path}")),
                expected,
                "{pattern} {path}"
            );
        }
    }
}
