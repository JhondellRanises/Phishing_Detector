<?php
/**
 * Phishing URL Detector - analysis logic
 */

declare(strict_types=1);

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

    $score = max(0, min(100, $score));

    $hasCritical = $isIpHost || $isShortener || $hasAt;
    $verdict = ($score >= 45 || $flagCount >= 2 || ($hasCritical && $score >= 30)) ? 'SUSPICIOUS' : 'SAFE';

    // Safe = score 0 and a clear message (no misleading warnings)
    if ($verdict === 'SAFE') {
        $score = 0;
        $reasons = ['No obvious phishing patterns detected.'];
    }

    return [
        'input_url' => $inputUrl,
        'normalized_url' => $normalized,
        'risk_score' => $score,
        'verdict' => $verdict,
        'reasons' => $reasons,
    ];
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

function find_suspicious_keywords(string $host, string $path, string $query): array
{
    $generic = ['login', 'verify', 'secure', 'banking', 'update', 'account'];
    $brands = ['paypal', 'microsoft', 'google'];
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
