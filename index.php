<?php
declare(strict_types=1);

require_once __DIR__ . '/PhishingDetector.php';

$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $url = (string)($_POST['url'] ?? '');
    $result = analyze_url($url);
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Phishing URL Detector</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: 'Inter', system-ui, sans-serif;
      background: linear-gradient(180deg, #eef2ff 0%, #f8fafc 40%, #f1f5f9 100%);
      min-height: 100vh;
      color: #1e293b;
    }

    .wrap {
      max-width: 560px;
      margin: 0 auto;
      padding: 2.5rem 1.25rem 4rem;
    }

    /* Card header */
    .card-header {
      text-align: center;
      padding: 1.75rem 1.75rem 1.25rem;
      border-bottom: 1px solid #f1f5f9;
    }

    .card-header h1 {
      font-size: 1.5rem;
      font-weight: 700;
      margin: 0 0 0.35rem;
      letter-spacing: -0.02em;
    }

    .card-header p {
      margin: 0;
      color: #64748b;
      font-size: 0.9rem;
      line-height: 1.5;
    }

    /* Card */
    .card {
      background: #fff;
      border-radius: 20px;
      box-shadow: 0 1px 3px rgba(0,0,0,.04), 0 12px 40px rgba(15,23,42,.08);
      border: 1px solid rgba(255,255,255,.8);
      overflow: hidden;
    }

    .section {
      padding: 1.75rem 1.75rem 1.5rem;
    }

    .section + .section {
      border-top: 1px solid #f1f5f9;
      padding-top: 1.5rem;
    }

    .section-label {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #94a3b8;
      margin-bottom: 0.85rem;
    }

    /* Form */
    .field-label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      color: #475569;
      margin-bottom: 0.5rem;
    }

    .input-row {
      display: flex;
      gap: 0.6rem;
    }

    .input-row input {
      flex: 1;
      padding: 0.8rem 1rem;
      font-size: 0.95rem;
      font-family: inherit;
      border: 1.5px solid #e2e8f0;
      border-radius: 12px;
      outline: none;
      transition: border-color .2s, box-shadow .2s;
    }

    .input-row input:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 4px rgba(59,130,246,.12);
    }

    .btn {
      padding: 0.8rem 1.4rem;
      font-size: 0.95rem;
      font-weight: 600;
      font-family: inherit;
      color: #fff;
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      border: none;
      border-radius: 12px;
      cursor: pointer;
      white-space: nowrap;
      box-shadow: 0 4px 14px rgba(37,99,235,.35);
      transition: transform .15s, box-shadow .15s;
    }

    .btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(37,99,235,.4);
    }

    .btn:active { transform: translateY(0); }

    /* Empty state */
    .empty {
      text-align: center;
      padding: 2rem 1rem;
      color: #94a3b8;
      font-size: 0.9rem;
      background: #f8fafc;
      border-radius: 14px;
      border: 1.5px dashed #e2e8f0;
    }

    /* Verdict */
    .verdict {
      display: flex;
      align-items: flex-start;
      gap: 1rem;
      padding: 1.25rem;
      border-radius: 14px;
      margin-bottom: 1.25rem;
    }

    .verdict.safe {
      background: linear-gradient(135deg, #f0fdf4, #ecfdf5);
      border: 1px solid #bbf7d0;
    }

    .verdict.suspicious {
      background: linear-gradient(135deg, #fef2f2, #fff1f2);
      border: 1px solid #fecaca;
    }

    .verdict-icon {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.3rem;
      flex-shrink: 0;
    }

    .verdict.safe .verdict-icon { background: #dcfce7; }
    .verdict.suspicious .verdict-icon { background: #fee2e2; }

    .verdict-title {
      font-size: 1.15rem;
      font-weight: 700;
      margin-bottom: 0.15rem;
    }

    .verdict.safe .verdict-title { color: #15803d; }
    .verdict.suspicious .verdict-title { color: #b91c1c; }

    .verdict-sub {
      font-size: 0.82rem;
      color: #64748b;
    }

    /* Score bar */
    .score-row {
      display: flex;
      justify-content: space-between;
      font-size: 0.82rem;
      color: #64748b;
      margin-bottom: 0.4rem;
    }

    .score-row strong { color: #1e293b; }

    .bar {
      height: 6px;
      background: #e2e8f0;
      border-radius: 99px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 99px;
    }

    .bar-fill.safe { background: linear-gradient(90deg, #4ade80, #22c55e); }
    .bar-fill.suspicious { background: linear-gradient(90deg, #f87171, #ef4444); }

    /* URL box */
    .url-block {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 0.9rem 1rem;
      margin-bottom: 1.25rem;
    }

    .url-block .lbl {
      font-size: 0.68rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: #94a3b8;
      margin-bottom: 0.4rem;
    }

    .url-block code {
      font-family: 'Consolas', 'Monaco', monospace;
      font-size: 0.84rem;
      word-break: break-all;
      color: #334155;
      line-height: 1.5;
    }

    /* Reasons */
    .reason {
      display: flex;
      align-items: flex-start;
      gap: 0.65rem;
      padding: 0.7rem 0.85rem;
      background: #f8fafc;
      border-radius: 10px;
      margin-bottom: 0.5rem;
      font-size: 0.88rem;
      color: #475569;
      line-height: 1.45;
    }

    .reason:last-child { margin-bottom: 0; }

    .reason-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #3b82f6;
      margin-top: 0.45rem;
      flex-shrink: 0;
    }

    .reason-safe .reason-dot {
      background: #22c55e;
    }

    @media (max-width: 520px) {
      .wrap { padding: 2rem 1rem 3rem; }
      .input-row { flex-direction: column; }
      .btn { width: 100%; }
    }
  </style>
</head>
<body>

<div class="wrap">
  <div class="card">
    <div class="card-header">
      <h1>Phishing URL Detector</h1>
      <p>Check if a link is safe or suspicious before you click it.</p>
    </div>

    <div class="section">
      <div class="section-label">Scan URL</div>
      <form method="post">
        <label class="field-label" for="url">Enter URL</label>
        <div class="input-row">
          <input
            type="url"
            id="url"
            name="url"
            placeholder="https://example.com"
            required
            value="<?= htmlspecialchars((string)($_POST['url'] ?? '')) ?>"
          >
          <button type="submit" class="btn">Scan</button>
        </div>
      </form>
    </div>

    <div class="section">
      <div class="section-label">Analysis Result</div>

      <?php if (!$result): ?>
        <div class="empty">No scan yet — enter a URL and click Scan.</div>
      <?php else: ?>
        <?php
          $score = (int)$result['risk_score'];
          $isSuspicious = $result['verdict'] === 'SUSPICIOUS';
          $cls = $isSuspicious ? 'suspicious' : 'safe';
        ?>

        <div class="verdict <?= $cls ?>">
          <div class="verdict-icon"><?= $isSuspicious ? '&#9888;' : '&#10003;' ?></div>
          <div style="flex:1">
            <div class="verdict-title"><?= $isSuspicious ? 'Suspicious' : 'Safe' ?></div>
            <div class="verdict-sub">Risk score: <?= $score ?> out of 100</div>
          </div>
        </div>

        <div class="score-row">
          <span>Risk level</span>
          <span><strong><?= $score ?></strong> / 100</span>
        </div>
        <div class="bar" style="margin-bottom:1.25rem">
          <div class="bar-fill <?= $cls ?>" style="width:<?= $score ?>%"></div>
        </div>

        <div class="url-block">
          <div class="lbl">Scanned URL</div>
          <code><?= htmlspecialchars($result['normalized_url']) ?></code>
        </div>

        <div class="section-label" style="margin-bottom:0.65rem">Why this result?</div>
        <?php foreach ($result['reasons'] as $reason): ?>
          <div class="reason<?= $isSuspicious ? '' : ' reason-safe' ?>">
            <span class="reason-dot"></span>
            <span><?= htmlspecialchars((string)$reason) ?></span>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </div>
</div>

</body>
</html>
