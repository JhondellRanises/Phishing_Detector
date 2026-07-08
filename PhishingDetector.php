<?php
/**
 * Phishing URL Detector - analysis logic
 */

declare(strict_types=1);

const KNOWN_BRANDS = ['google', 'paypal', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix', 'instagram'];

const TRUSTED_BRAND_SUBDOMAINS = [
    'www', 'm', 'mobile', 'mail', 'news', 'support', 'help', 'developers', 'cloud',
    'apis', 'play', 'maps', 'drive', 'docs', 'calendar', 'photos', 'accounts', 'my',
];

const SUSPICIOUS_SUBDOMAINS = [
    'user', 'login', 'signin', 'secure', 'verify', 'account', 'banking', 'update',
    'auth', 'password', 'wallet', 'payment', 'confirm', 'billing', 'security',
];

function analyze_url(string $inputUrl): array
{
    $inputUrl = trim($inputUrl);
    $normalized = normalize_url($inputUrl);
    $parts = @parse_url($normalized);

    $reasons = [];
    $score = 0;
    $flagCount = 0;

    if (!$parts || empty($parts['host'])) {
        return [
            'input_url' => $inputUrl,
            'normalized_url' => $normalized,
            'risk_score' => 100,
            'verdict' => 'SUSPICIOUS',
            'reasons' => ['Invalid or unparseable URL.'],
        ];
    }

    $host = strtolower((string)$parts['host']);
    $path = strtolower((string)($parts['path'] ?? ''));
    $query = strtolower((string)($parts['query'] ?? ''));
    $isIpHost = filter_var($host, FILTER_VALIDATE_IP) !== false;

    // Raw IP address
    if ($isIpHost) {
        $score += 35;
        $flagCount++;
        $reasons[] = 'Uses a raw IP address instead of a domain name.';
    }

    // Long URL
    $len = strlen($normalized);
    if ($len > 120) {
        $score += 20;
        $flagCount++;
        $reasons[] = 'URL is very long (over 120 characters).';
    } elseif ($len > 75) {
        $score += 12;
        $flagCount++;
        $reasons[] = 'URL is long (over 75 characters).';
    }

    // Excessive subdomains (skip for IP addresses)
    if (!$isIpHost) {
        $labelCount = count(get_host_labels($host));
        if ($labelCount >= 6) {
            $score += 20;
            $flagCount++;
            $reasons[] = 'Has excessive subdomains (6+ domain parts).';
        } elseif ($labelCount >= 4) {
            $score += 12;
            $flagCount++;
            $reasons[] = 'Has many subdomains (4+ domain parts).';
        }
    }

    // Suspicious keywords (smart matching — no false hits on real domains)
    $matched = find_suspicious_keywords($host, $path, $query);
    if (!empty($matched)) {
        $score += min(48, count($matched) * 12);
        $flagCount++;
        $reasons[] = 'Contains suspicious keyword(s): ' . implode(', ', $matched) . '.';
    }

    // Typosquatting / misspelled brand domains (e.g. gooogle.com, paypa1.com)
    $typosquat = find_typosquat_brand($host);
    if ($typosquat !== null) {
        $score += 55;
        $flagCount++;
        $reasons[] = 'Domain name closely resembles "' . $typosquat['brand'] . '" but is misspelled (' . $typosquat['found'] . ').';
    }

    // Suspicious subdomains on real brand domains (e.g. user.google.com)
    $suspiciousSub = find_suspicious_brand_subdomain($host);
    if ($suspiciousSub !== null) {
        $score += 50;
        $flagCount++;
        $reasons[] = 'Uses a suspicious subdomain ("' . $suspiciousSub . '") on a known brand domain.';
    }

    // Brand name embedded in a non-official domain (e.g. google-user.com)
    $fakeBrand = find_brand_in_fake_domain($host);
    if ($fakeBrand !== null) {
        $score += 50;
        $flagCount++;
        $reasons[] = 'Uses the brand name "' . $fakeBrand . '" in a non-official domain.';
    }

    // URL shorteners
    $shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'tiny.cc', 'rebrand.ly', 'shorturl.at', 'rb.gy', 'lnkd.in'];
    $isShortener = in_array($host, $shorteners, true);
    if ($isShortener) {
        $score += 35;
        $flagCount++;
        $reasons[] = 'Uses a known URL shortener (often used to hide the real destination).';
    }

    // @ symbol in URL
    $hasAt = str_contains($normalized, '@');
    if ($hasAt) {
        $score += 40;
        $flagCount++;
        $reasons[] = "Contains '@' which can hide the real destination (userinfo trick).";
    }

    // Domain / URL existence on the internet
    $hostExists = host_exists_on_internet($host);
    if (!$hostExists) {
        $score += 60;
        $flagCount++;
        $reasons[] = 'Domain does not exist on the internet (possibly fake or made-up URL).';
    }

    $score = max(0, min(100, $score));

    $hasCritical = $isIpHost || $isShortener || $hasAt || $typosquat !== null
        || $suspiciousSub !== null || $fakeBrand !== null || !$hostExists;
    $verdict = ($score >= 45 || $flagCount >= 2 || ($hasCritical && $score >= 30)) ? 'SUSPICIOUS' : 'SAFE';

    if ($verdict === 'SAFE') {
        $score = 0;
        $reasons = ['URL exists on the internet and no obvious phishing patterns were detected.'];
    }

    return [
        'input_url' => $inputUrl,
        'normalized_url' => $normalized,
        'risk_score' => $score,
        'verdict' => $verdict,
        'reasons' => $reasons,
    ];
}

function host_exists_on_internet(string $host): bool
{
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    if (function_exists('dns_get_record')) {
        foreach ([DNS_A, DNS_AAAA, DNS_CNAME] as $type) {
            $records = @dns_get_record($host, $type);
            if (is_array($records) && $records !== []) {
                return true;
            }
        }
    }

    if (@checkdnsrr($host, 'A') || @checkdnsrr($host, 'AAAA') || @checkdnsrr($host, 'CNAME')) {
        return true;
    }

    $resolved = @gethostbyname($host);
    if (is_string($resolved) && $resolved !== '' && $resolved !== $host) {
        return true;
    }

    return false;
}

function normalize_url(string $url): string
{
    $url = trim($url);
    if ($url === '') {
        return '';
    }
    if (!preg_match('~^[a-z][a-z0-9+.-]*://~i', $url)) {
        $url = 'https://' . $url;
    }
    return $url;
}

function get_host_labels(string $host): array
{
    return array_values(array_filter(explode('.', strtolower($host)), static fn($x) => $x !== ''));
}

function get_main_domain_label(string $host): string
{
    $labels = get_host_labels($host);
    if (count($labels) < 2) {
        return $labels[0] ?? '';
    }
    return $labels[count($labels) - 2];
}

function split_label_parts(string $label): array
{
    return preg_split('/[-_]+/', strtolower($label)) ?: [];
}

function keyword_in_label(string $label, string $keyword): bool
{
    $keyword = strtolower($keyword);
    $label = strtolower($label);
    if ($label === $keyword) {
        return true;
    }
    return in_array($keyword, split_label_parts($label), true);
}

function keyword_in_path(string $path, string $query, string $keyword): bool
{
    $keyword = strtolower($keyword);
    $target = strtolower($path . '?' . $query);
    $segments = array_filter(explode('/', trim($path, '/')));
    foreach ($segments as $segment) {
        if ($segment === $keyword || in_array($keyword, split_label_parts($segment), true)) {
            return true;
        }
    }
    return str_contains($target, $keyword);
}

function is_legitimate_brand_host(string $host, string $brand): bool
{
    return get_main_domain_label($host) === strtolower($brand);
}

function brand_used_as_impersonation(string $host, string $path, string $query, string $brand): bool
{
    if (is_legitimate_brand_host($host, $brand)) {
        return false;
    }

    $labels = get_host_labels($host);
    $mainIndex = max(0, count($labels) - 2);

    foreach ($labels as $index => $label) {
        if ($index < $mainIndex && keyword_in_label($label, $brand)) {
            return true;
        }
    }

    return keyword_in_path($path, $query, $brand);
}

function normalize_homoglyphs(string $label): string
{
    return strtr(strtolower($label), [
        '0' => 'o',
        '1' => 'l',
        '3' => 'e',
        '5' => 's',
        '@' => 'a',
    ]);
}

function is_typosquat_of_brand(string $label, string $brand): bool
{
    $label = strtolower($label);
    $brand = strtolower($brand);

    if ($label === $brand) {
        return false;
    }

    $normalized = normalize_homoglyphs($label);
    if ($normalized === $brand) {
        return true;
    }

    $maxLen = max(strlen($label), strlen($brand));
    if ($maxLen < 4 || abs(strlen($label) - strlen($brand)) > 2) {
        return false;
    }

    $distance = levenshtein($label, $brand);
    if ($distance >= 1 && $distance <= 2) {
        return true;
    }

    $normalizedDistance = levenshtein($normalized, $brand);
    return $normalizedDistance >= 1 && $normalizedDistance <= 2;
}

function find_typosquat_brand(string $host): ?array
{
    $labels = get_host_labels($host);
    if (count($labels) < 2) {
        return null;
    }

    $domainLabel = $labels[count($labels) - 2];

    foreach (KNOWN_BRANDS as $brand) {
        if ($domainLabel === $brand) {
            return null;
        }
        if (is_typosquat_of_brand($domainLabel, $brand)) {
            return ['brand' => $brand, 'found' => $domainLabel];
        }
    }

    return null;
}

function find_brand_in_fake_domain(string $host): ?string
{
    foreach (KNOWN_BRANDS as $brand) {
        if (is_legitimate_brand_host($host, $brand)) {
            continue;
        }
        foreach (get_host_labels($host) as $label) {
            if (keyword_in_label($label, $brand)) {
                return $brand;
            }
        }
    }

    return null;
}

function find_suspicious_brand_subdomain(string $host): ?string
{
    $labels = get_host_labels($host);
    if (count($labels) < 3) {
        return null;
    }

    $brandLabel = $labels[count($labels) - 2];
    if (!in_array($brandLabel, KNOWN_BRANDS, true)) {
        return null;
    }

    $subdomainCount = count($labels) - 2;
    for ($i = 0; $i < $subdomainCount; $i++) {
        $sub = $labels[$i];
        if (in_array($sub, TRUSTED_BRAND_SUBDOMAINS, true)) {
            continue;
        }
        if (in_array($sub, SUSPICIOUS_SUBDOMAINS, true)) {
            return $sub;
        }
        foreach (SUSPICIOUS_SUBDOMAINS as $keyword) {
            if (keyword_in_label($sub, $keyword)) {
                return $sub;
            }
        }
    }

    return null;
}

function find_suspicious_keywords(string $host, string $path, string $query): array
{
    $generic = ['login', 'verify', 'secure', 'banking', 'update', 'account'];
    $brands = KNOWN_BRANDS;
    $matched = [];

    foreach ($generic as $keyword) {
        $found = false;
        foreach (get_host_labels($host) as $label) {
            if (keyword_in_label($label, $keyword)) {
                $found = true;
                break;
            }
        }
        if (!$found && keyword_in_path($path, $query, $keyword)) {
            $found = true;
        }
        if ($found) {
            $matched[] = $keyword;
        }
    }

    foreach ($brands as $brand) {
        if (brand_used_as_impersonation($host, $path, $query, $brand)) {
            $matched[] = $brand;
        }
    }

    return array_values(array_unique($matched));
}
