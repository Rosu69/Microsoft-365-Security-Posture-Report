# ============================================================
#  Microsoft 365 Security Posture Scorer
#  Read-only | Safe for production | No changes made
#  Permissions: SecurityEvents.Read.All, Directory.Read.All
# ============================================================

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# ===========================
#  CONNECT
# ===========================
Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "SecurityEvents.Read.All", "SecurityActions.Read.All", "Policy.Read.All", "Directory.Read.All"

# ===========================
#  PULL SECURE SCORE DATA
# ===========================
Write-Host "[*] Pulling Microsoft Secure Score..." -ForegroundColor Cyan

$secureScoreUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"
$secureScoreData = Invoke-MgGraphRequest -Uri $secureScoreUri -Method GET
$latestScore = $secureScoreData.value[0]

$currentScore   = [math]::Round($latestScore.currentScore, 1)
$maxScore       = [math]::Round($latestScore.maxScore, 1)
$rawPercentage  = [math]::Round(($currentScore / $maxScore) * 100, 1)
$tenantId       = $latestScore.azureTenantId
$scoreDate      = $latestScore.createdDateTime

Write-Host "    Current Score: $currentScore / $maxScore ($rawPercentage%)" -ForegroundColor Gray

# ===========================
#  PULL ALL CONTROL PROFILES
# ===========================
Write-Host "[*] Pulling all Secure Score control profiles..." -ForegroundColor Cyan

$controlsUri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?`$top=999"
$controlsData = Invoke-MgGraphRequest -Uri $controlsUri -Method GET
$controls = $controlsData.value

Write-Host "    Found $($controls.Count) control profiles." -ForegroundColor Gray

# ===========================
#  PULL CURRENT CONTROL SCORES
# ===========================
Write-Host "[*] Pulling current control scores..." -ForegroundColor Cyan

$controlScoresRaw = $latestScore.controlScores
$controlScoreLookup = @{}
foreach ($cs in $controlScoresRaw) {
    $controlScoreLookup[$cs.controlName] = $cs
}

# ===========================
#  NIST CSF MAPPING TABLE
# ===========================
$nistMapping = @{
    "Identity"        = "Protect"
    "Device"          = "Protect"
    "Data"            = "Protect"
    "Apps"            = "Detect"
    "Infrastructure"  = "Identify"
}

# ===========================
#  CIS BENCHMARK MAPPING TABLE
# ===========================
$cisMapping = @{
    "Identity"       = "CIS Control 6 - Access Control Management"
    "Device"         = "CIS Control 4 - Secure Configuration / Control 10 - Malware Defense"
    "Data"           = "CIS Control 3 - Data Protection"
    "Apps"           = "CIS Control 16 - Application Software Security"
    "Infrastructure" = "CIS Control 1 - Inventory and Control of Enterprise Assets"
}

# ===========================
#  CATEGORY WEIGHTS
# ===========================
$categoryWeights = @{
    "Identity"       = 0.35
    "Device"         = 0.25
    "Data"           = 0.20
    "Apps"           = 0.12
    "Infrastructure" = 0.08
}

# ===========================
#  PROCESS CONTROLS
# ===========================
Write-Host "[*] Processing and scoring controls..." -ForegroundColor Cyan

$processedControls = @()
$categoryScores    = @{}
$categoryMaxes     = @{}

foreach ($control in $controls) {
    $name        = $control.id
    $title       = $control.title
    $category    = $control.controlCategory
    $maxPoints   = $control.maxScore
    $remediation = $control.remediation
    $actionType  = $control.controlStateUpdates

    # Get current score for this control
    $currentPoints = 0
    $scoreState    = "unknown"
    if ($controlScoreLookup.ContainsKey($name)) {
        $currentPoints = $controlScoreLookup[$name].score
        $scoreState    = $controlScoreLookup[$name].scoreInPercentage
    }

    $implemented = $currentPoints -ge $maxPoints
    $gap         = $maxPoints - $currentPoints
    $nist        = if ($nistMapping.ContainsKey($category)) { $nistMapping[$category] } else { "Protect" }
    $cis         = if ($cisMapping.ContainsKey($category))  { $cisMapping[$category]  } else { "CIS Control 1" }
    $weight      = if ($categoryWeights.ContainsKey($category)) { $categoryWeights[$category] } else { 0.05 }

    # Build category accumulators
    if (-not $categoryScores.ContainsKey($category)) {
        $categoryScores[$category] = 0
        $categoryMaxes[$category]  = 0
    }
    $categoryScores[$category] += $currentPoints
    $categoryMaxes[$category]  += $maxPoints

    # Priority score = gap points x category weight (higher = fix this first)
    $priorityScore = [math]::Round($gap * $weight * 100, 2)

    $processedControls += [PSCustomObject]@{
        Name          = $name
        Title         = $title
        Category      = $category
        CurrentPoints = [math]::Round($currentPoints, 1)
        MaxPoints     = [math]::Round($maxPoints, 1)
        Gap           = [math]::Round($gap, 1)
        Implemented   = $implemented
        Status        = if ($implemented) { "Complete" } elseif ($currentPoints -gt 0) { "Partial" } else { "Not Started" }
        NISTFunction  = $nist
        CISControl    = $cis
        PriorityScore = $priorityScore
        Remediation   = if ($remediation) { $remediation } else { "See Microsoft Secure Score portal" }
    }
}

# ===========================
#  WEIGHTED SCORE CALCULATION
# ===========================
$weightedScore = 0
foreach ($cat in $categoryScores.Keys) {
    if ($categoryMaxes[$cat] -gt 0) {
        $catPct    = $categoryScores[$cat] / $categoryMaxes[$cat]
        $weight    = if ($categoryWeights.ContainsKey($cat)) { $categoryWeights[$cat] } else { 0.05 }
        $weightedScore += $catPct * $weight * 100
    }
}
$weightedScore = [math]::Round($weightedScore, 1)

# ===========================
#  POSTURE GRADE
# ===========================
$postureGrade = switch ($weightedScore) {
    { $_ -ge 85 } { "A - Strong"    }
    { $_ -ge 70 } { "B - Good"      }
    { $_ -ge 55 } { "C - Moderate"  }
    { $_ -ge 40 } { "D - Weak"      }
    default        { "F - Critical"  }
}

# ===========================
#  TOP 10 QUICK WINS
# ===========================
$quickWins = $processedControls |
    Where-Object { -not $_.Implemented } |
    Sort-Object PriorityScore -Descending |
    Select-Object -First 10

# ===========================
#  NIST FUNCTION SUMMARY
# ===========================
$nistSummary = $processedControls | Group-Object NISTFunction | ForEach-Object {
    $implemented = ($_.Group | Where-Object { $_.Implemented }).Count
    $total       = $_.Count
    [PSCustomObject]@{
        Function    = $_.Name
        Implemented = $implemented
        Total       = $total
        Percentage  = [math]::Round(($implemented / $total) * 100, 0)
    }
}

# ===========================
#  TERMINAL PREVIEW
# ===========================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  MICROSOFT 365 SECURITY POSTURE REPORT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Raw Microsoft Score : $currentScore / $maxScore ($rawPercentage%)"
Write-Host "  Weighted Score      : $weightedScore / 100"
Write-Host "  Posture Grade       : $postureGrade"
Write-Host "  Controls Evaluated  : $($processedControls.Count)"
Write-Host ""
Write-Host "  TOP 10 PRIORITY FIXES:" -ForegroundColor Yellow
$quickWins | Format-Table Title, Category, Gap, PriorityScore -AutoSize

# ===========================
#  CSV EXPORT
# ===========================
$csvPath = ".\M365-Posture-Report.csv"
$processedControls | Sort-Object PriorityScore -Descending | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "[+] CSV saved: $csvPath" -ForegroundColor Green

# ===========================
#  HTML REPORT
# ===========================
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$gradeColor = switch -Wildcard ($postureGrade) {
    "A*" { "#107c10" }
    "B*" { "#0078d4" }
    "C*" { "#b38600" }
    "D*" { "#e65c00" }
    default { "#c00"  }
}

$completeCount  = ($processedControls | Where-Object { $_.Status -eq "Complete"    }).Count
$partialCount   = ($processedControls | Where-Object { $_.Status -eq "Partial"     }).Count
$notStartCount  = ($processedControls | Where-Object { $_.Status -eq "Not Started" }).Count

# Build category breakdown rows
$catRows = ""
foreach ($cat in $categoryScores.Keys | Sort-Object) {
    $catMax = $categoryMaxes[$cat]
    $catCur = $categoryScores[$cat]
    $catPct = if ($catMax -gt 0) { [math]::Round(($catCur / $catMax) * 100, 0) } else { 0 }
    $barColor = if ($catPct -ge 70) { "#107c10" } elseif ($catPct -ge 40) { "#b38600" } else { "#c00" }
    $nistFunc = if ($nistMapping.ContainsKey($cat)) { $nistMapping[$cat] } else { "Protect" }
    $cisCtrl  = if ($cisMapping.ContainsKey($cat))  { $cisMapping[$cat]  } else { "-" }
    $catRows += "<tr><td><strong>$cat</strong></td><td>$([math]::Round($catCur,1)) / $([math]::Round($catMax,1))</td><td><div style='background:#eee;border-radius:4px;height:14px;width:200px'><div style='background:$barColor;width:$catPct%;height:14px;border-radius:4px'></div></div> $catPct%</td><td>$nistFunc</td><td style='font-size:0.8rem'>$cisCtrl</td></tr>"
}

# Build quick wins rows
$qwRows = ""
$qwNum  = 1
foreach ($qw in $quickWins) {
    $statusColor = if ($qw.Status -eq "Partial") { "#b38600" } else { "#c00" }
    $qwRows += "<tr><td>$qwNum</td><td><strong>$($qw.Title)</strong></td><td>$($qw.Category)</td><td>$($qw.Gap)</td><td><span style='color:$statusColor;font-weight:bold'>$($qw.Status)</span></td><td>$($qw.NISTFunction)</td><td style='font-size:0.78rem'>$($qw.CISControl)</td></tr>"
    $qwNum++
}

# Build NIST summary rows
$nistRows = ""
foreach ($n in $nistSummary | Sort-Object Percentage) {
    $barColor = if ($n.Percentage -ge 70) { "#107c10" } elseif ($n.Percentage -ge 40) { "#b38600" } else { "#c00" }
    $nistRows += "<tr><td><strong>$($n.Function)</strong></td><td>$($n.Implemented) / $($n.Total)</td><td><div style='background:#eee;border-radius:4px;height:14px;width:200px'><div style='background:$barColor;width:$($n.Percentage)%;height:14px;border-radius:4px'></div></div> $($n.Percentage)%</td></tr>"
}

# Build all controls table
$allRows = ""
foreach ($c in ($processedControls | Sort-Object PriorityScore -Descending)) {
    $statusColor = switch ($c.Status) {
        "Complete"    { "color:#107c10;font-weight:bold" }
        "Partial"     { "color:#b38600;font-weight:bold" }
        "Not Started" { "color:#c00;font-weight:bold"    }
        default       { "" }
    }
    $allRows += "<tr><td>$($c.Title)</td><td>$($c.Category)</td><td style='$statusColor'>$($c.Status)</td><td>$($c.CurrentPoints) / $($c.MaxPoints)</td><td>$($c.NISTFunction)</td><td style='font-size:0.78rem'>$($c.CISControl)</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>M365 Security Posture Report</title>
<style>
  body      { font-family: Segoe UI, Tahoma, sans-serif; padding: 2rem; background: #f4f6f9; color: #333; margin: 0; }
  h1        { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 0.5rem; }
  h2        { color: #0078d4; margin-top: 2rem; }
  .hero     { display: flex; gap: 1.5rem; align-items: center; background: white; border-radius: 12px;
              padding: 1.5rem 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin: 1.5rem 0; flex-wrap: wrap; }
  .grade    { font-size: 4rem; font-weight: 900; color: $gradeColor; line-height: 1; }
  .scores   { display: flex; flex-direction: column; gap: 0.3rem; }
  .scores p { margin: 0; font-size: 1rem; }
  .scores .label { font-size: 0.8rem; color: #888; }
  .summary  { display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }
  .card     { background: white; border-radius: 8px; padding: 1rem 1.5rem; min-width: 110px;
              box-shadow: 0 2px 6px rgba(0,0,0,0.08); text-align: center; }
  .card h3  { margin: 0; font-size: 2rem; }
  .card p   { margin: 0.3rem 0 0; font-size: 0.82rem; color: #666; }
  table     { width: 100%; border-collapse: collapse; background: white; border-radius: 8px;
              overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.08); margin-bottom: 2rem; }
  th        { background: #0078d4; color: white; padding: 11px 14px; text-align: left; font-size: 0.88rem; }
  td        { padding: 9px 14px; border-bottom: 1px solid #eee; font-size: 0.85rem; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td      { background: #f0f6ff; }
  .safe-note { background: #dff6dd; border-left: 4px solid #107c10; padding: 0.75rem 1rem;
               border-radius: 4px; margin-bottom: 1.5rem; font-size: 0.88rem; }
  footer    { margin-top: 2rem; font-size: 0.8rem; color: #999; border-top: 1px solid #ddd; padding-top: 1rem; }
</style>
</head>
<body>
<h1>Microsoft 365 Security Posture Report</h1>
<p>Generated: $timestamp</p>
<div class="safe-note">Read-only audit using Microsoft Graph API. No settings, policies, or configurations were modified.</div>

<div class="hero">
  <div class="grade">$($postureGrade.Split('-')[0].Trim())</div>
  <div class="scores">
    <p class="label">POSTURE GRADE</p>
    <p><strong style="font-size:1.2rem">$postureGrade</strong></p>
    <p class="label" style="margin-top:0.5rem">WEIGHTED SCORE (risk-adjusted)</p>
    <p><strong style="font-size:1.5rem;color:#0078d4">$weightedScore / 100</strong></p>
    <p class="label">RAW MICROSOFT SECURE SCORE</p>
    <p>$currentScore / $maxScore ($rawPercentage%)</p>
  </div>
</div>

<div class="summary">
  <div class="card"><h3 style="color:#107c10">$completeCount</h3><p>Complete</p></div>
  <div class="card"><h3 style="color:#b38600">$partialCount</h3><p>Partial</p></div>
  <div class="card"><h3 style="color:#c00">$notStartCount</h3><p>Not Started</p></div>
  <div class="card"><h3>$($processedControls.Count)</h3><p>Total Controls</p></div>
</div>

<h2>Score by Category (Weighted)</h2>
<table>
<thead><tr><th>Category</th><th>Score</th><th>Progress</th><th>NIST CSF Function</th><th>CIS Benchmark</th></tr></thead>
<tbody>$catRows</tbody>
</table>

<h2>NIST CSF Coverage</h2>
<table>
<thead><tr><th>NIST Function</th><th>Controls Implemented</th><th>Coverage</th></tr></thead>
<tbody>$nistRows</tbody>
</table>

<h2>Top 10 Priority Fixes (Highest Impact)</h2>
<table>
<thead><tr><th>#</th><th>Control</th><th>Category</th><th>Points Gap</th><th>Status</th><th>NIST</th><th>CIS Control</th></tr></thead>
<tbody>$qwRows</tbody>
</table>

<h2>All Controls</h2>
<table>
<thead><tr><th>Control</th><th>Category</th><th>Status</th><th>Score</th><th>NIST</th><th>CIS Control</th></tr></thead>
<tbody>$allRows</tbody>
</table>

<footer>Generated by M365-Posture-Scorer.ps1 | Read-only audit | Microsoft Graph API | No tenant changes made</footer>
</body>
</html>
"@

$htmlPath = ".\M365-Posture-Report.html"
$html | Out-File $htmlPath -Encoding UTF8
Write-Host "[+] HTML report saved and opening: $htmlPath" -ForegroundColor Green
Start-Process $htmlPath

Write-Host "`n[DONE] Posture scoring complete." -ForegroundColor Cyan
Write-Host "  Weighted Score : $weightedScore / 100"
Write-Host "  Grade          : $postureGrade"
Write-Host "  CSV            : $csvPath"
Write-Host "  HTML           : $htmlPath`n"