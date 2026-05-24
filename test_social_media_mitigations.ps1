##############################################################
#  Social Media Attack — End-to-End Mitigation Test
#  Tests 5 representative scenarios through the full pipeline
#  Usage:  powershell.exe -File test_social_media_mitigations.ps1
##############################################################

$b = 'http://localhost:8888'
$pass = 0; $fail = 0; $results = @()

function Header($t) { Write-Host "`n$('='*65)`n  $t`n$('='*65)" -ForegroundColor Cyan }
function OK($m)     { Write-Host "  [PASS] $m" -ForegroundColor Green;  $global:pass++ }
function FAIL($m)   { Write-Host "  [FAIL] $m" -ForegroundColor Red;    $global:fail++ }
function INFO($m)   { Write-Host "  [INFO] $m" -ForegroundColor Yellow }

# ── 1. Health check ──────────────────────────────────────────────────
Header "Pre-flight: System Health"
try {
    $h = Invoke-RestMethod "$b/api/health" -ErrorAction Stop
    if ($h.status -eq 'healthy') { OK "Server healthy" }
    else                          { FAIL "Server status: $($h.status)" }
    INFO "Events: $($h.events_count)  Patterns: $($h.patterns_count)  Mitigations: $($h.mitigations_count)"
} catch {
    FAIL "Server unreachable — start with: python main.py"
    exit 1
}

# ── Test scenarios ────────────────────────────────────────────────────
$scenarios = @(
    @{
        name    = "LinkedIn APT29 Recruiter Phishing"
        text    = "APT29 fake LinkedIn recruiter profile linkedin-recruiter-apt29.com harvesting Microsoft SSO credentials from NATO defence contractor employees. 73 confirmed victims. Cobalt Strike beacon deployed post-compromise to 185.220.101.55. Lateral movement and 8.3GB exfiltration detected. CVE-2024-21338 exploited."
        expects = @("phish","credential","lateral","cobalt","apt","mitigat","block","mfa","aware")
    },
    @{
        name    = "WhatsApp Vultur Banking Trojan"
        text    = "Vultur banking trojan APK (hash b3e7f1a9c5d2e4f8a0b6c3d7e9f1a4b8) spread via WhatsApp as fake HSBC security update. 15,000 infections in UK/Australia/Singapore. Malware intercepts OTP SMS codes and streams device screen to C2 at 103.245.58.77. Real-time banking fraud: £2.8M stolen."
        expects = @("trojan","mobile","banking","otp","sms","mitigat","block","monitor")
    },
    @{
        name    = "Twitter/X Verified Account Takeover"
        text    = "Twitter OAuth phishing campaign: 500 verified journalist accounts compromised via x-account-verify.secure-login-twitter.com using adversary-in-the-middle proxy bypassing 2FA. Compromised accounts immediately posted coordinated crypto pump-and-dump scam content to millions of followers. Estimated $3.2M fraud."
        expects = @("phish","account","takeover","oauth","social","mitigat","2fa","monitor")
    },
    @{
        name    = "Lazarus Group Telegram DeFi Attack"
        text    = "Lazarus Group TraderTraitor sub-group targeted DeFi developers via Telegram and LinkedIn. Fake crypto trader personas built over 4-6 weeks. Delivered RustBucket macOS backdoor and Windows RAT (hash c7a2b5e8f3d6a9c1b4e7f0a3d6b9c2e5) via 'trading algorithm' ZIP from 91.108.56.199. 50 victims, $47M crypto stolen."
        expects = @("apt","backdoor","social engineer","mitigat","endpoint","network","dprk","lazarus")
    },
    @{
        name    = "Reddit Web3 Wallet Drainer"
        text    = "Coordinated Reddit campaign using 1,200 aged bot accounts promoted fake Ethereum airdrop on r/CryptoCurrency. 180,000 users directed to reddit-airdrop-crypto.scam-relay.io. Malicious Web3 approve transaction drains MetaMask wallets. Chrome extension (MD5: f1e4d7a0b3c6e9f2a5b8c1d4e7f0a3b6) replaces clipboard wallet addresses. $2.1M stolen in 6 hours."
        expects = @("web3","crypto","wallet","extension","mitigat","block","aware")
    }
)

# ── Run each scenario through instant pipeline ───────────────────────
foreach ($s in $scenarios) {
    Header "TEST: $($s.name)"
    INFO "Submitting to /api/ingest/instant ..."

    try {
        $body = @{ text = $s.text } | ConvertTo-Json -Compress
        $r = Invoke-RestMethod "$b/api/ingest/instant" `
             -Method POST `
             -ContentType 'application/json' `
             -Body $body `
             -ErrorAction Stop

        # Basic checks
        if ($r.event_id) { OK "Event ID: $($r.event_id)" } else { FAIL "No event_id returned" }
        INFO "Severity : $($r.severity)"

        # Enrichment (O1)
        if ($r.enriched) {
            $en = $r.enriched
            OK "Enrichment (O1): category='$($en.threat_category)'  stage='$($en.attack_stage)'  confidence=$([math]::Round($en.enrichment_confidence*100))%"
            if ($en.ttps -and $en.ttps.Count -gt 0) {
                OK "  TTPs extracted ($($en.ttps.Count)): $($en.ttps[0..2] -join ' | ')"
            } else { FAIL "  No TTPs extracted" }
            if ($en.mitre_tactics -and $en.mitre_tactics.Count -gt 0) {
                INFO "  MITRE Tactics: $($en.mitre_tactics -join ', ')"
            }
        } else { FAIL "Enrichment returned null" }

        # Classification (O2)
        if ($r.classification) {
            $cl = $r.classification
            OK "Classification (O2): '$($cl.threat_category)' | stage='$($cl.attack_stage)' | conf=$([math]::Round($cl.classification_confidence*100))%"
        } else { FAIL "Classification returned null" }

        # Patterns
        INFO "Patterns discovered: $($r.patterns_found)"

        # Mitigations (O3)  ← KEY CHECK
        if ($r.mitigations -and $r.mitigations.Count -gt 0) {
            OK "Mitigations (O3): $($r.mitigations.Count) generated, $($r.validated) validated"
            foreach ($m in $r.mitigations) {
                $tick = if ($m.validated) { "[V]" } else { "[ ]" }
                INFO "  $tick $($m.title) | Priority=$($m.priority)"
                if ($m.description) {
                    INFO "      $($m.description.Substring(0, [Math]::Min(100, $m.description.Length)))..."
                }
                if ($m.steps -and $m.steps.Count -gt 0) {
                    INFO "      Steps: $($m.steps.Count) action steps defined"
                    INFO "        1. $($m.steps[0])"
                    if ($m.steps.Count -gt 1) { INFO "        2. $($m.steps[1])" }
                }
                if ($m.mitre_d3fend -and $m.mitre_d3fend.Count -gt 0) {
                    INFO "      D3FEND: $($m.mitre_d3fend -join ', ')"
                }
            }

            # Check mitigation relevance — does it mention expected keywords?
            $mitText = ($r.mitigations | ForEach-Object { "$($_.title) $($_.description)" }) -join " "
            $chatText = $r.chat_summary
            $allText  = "$mitText $chatText".ToLower()
            $hit = 0
            foreach ($kw in $s.expects) {
                if ($allText -match $kw) { $hit++ }
            }
            $relevancePct = [math]::Round(($hit / $s.expects.Count) * 100)
            if ($relevancePct -ge 50) {
                OK "Relevance score: $relevancePct% ($hit/$($s.expects.Count) keywords matched) — RELEVANT"
            } else {
                FAIL "Relevance score: $relevancePct% ($hit/$($s.expects.Count) keywords matched) — TOO GENERIC"
            }
        } else {
            FAIL "NO MITIGATIONS GENERATED — pipeline may not have patterns yet"
        }

        # Chatbot summary
        if ($r.chat_summary -and $r.chat_summary.Length -gt 20) {
            OK "Chatbot summary: $($r.chat_summary.Substring(0, [Math]::Min(120, $r.chat_summary.Length)))..."
        } else {
            FAIL "No chatbot summary"
        }

        $results += [PSCustomObject]@{
            Scenario    = $s.name
            EventID     = $r.event_id
            Severity    = $r.severity
            Mitigations = if ($r.mitigations) { $r.mitigations.Count } else { 0 }
            Validated   = $r.validated
            Relevance   = "$relevancePct%"
        }

    } catch {
        FAIL "Request failed: $($_.Exception.Message)"
        $results += [PSCustomObject]@{ Scenario=$s.name; EventID='ERROR'; Severity=''; Mitigations=0; Validated=0; Relevance='0%' }
    }
}

# ── Chatbot verification ──────────────────────────────────────────────
Header "Chatbot Verification"

$chatTests = @(
    @{ q="show mitigations";          k="mitigation" }
    @{ q="what's complete?";          k="processed" }
    @{ q="show patterns";             k="pattern" }
    @{ q="my last submission";        k="Threat" }
)
foreach ($t in $chatTests) {
    try {
        $cr = Invoke-RestMethod "$b/api/chat" -Method POST `
              -ContentType 'application/json' `
              -Body (@{message=$t.q} | ConvertTo-Json -Compress) -ErrorAction Stop
        $reply = $cr.reply
        if ($reply -match $t.k -or $reply.Length -gt 30) {
            OK "Chat '$($t.q)' → $($reply.Substring(0,[Math]::Min(80,$reply.Length)))..."
        } else {
            FAIL "Chat '$($t.q)' → unexpected: $reply"
        }
    } catch { FAIL "Chat '$($t.q)' failed: $($_.Exception.Message)" }
}

# ── Benchmark check ───────────────────────────────────────────────────
Header "O4 Benchmark — Precision / Recall / F1"
try {
    $bm = Invoke-RestMethod "$b/api/benchmark/run" -Method POST -ErrorAction Stop
    OK "Benchmark run_id: $($bm.run_id)"
    INFO "  Events tested        : $($bm.total_events_tested)"
    INFO "  TTP extraction rate  : $([math]::Round($bm.ttp_extraction_rate*100,1))%"
    INFO "  Avg enrichment conf  : $([math]::Round($bm.avg_enrichment_confidence*100,1))%"
    INFO "  Avg classify conf    : $([math]::Round($bm.avg_classification_confidence*100,1))%"
    INFO "  Mitigation relevance : $([math]::Round($bm.avg_mitigation_relevance*100,1))%"
    if ($bm.ttp_extraction_rate -ge 0.5) { OK "TTP extraction rate acceptable (≥50%)" }
    else { FAIL "TTP extraction rate below 50% — LLM may need better prompts" }
} catch {
    FAIL "Benchmark failed: $($_.Exception.Message)"
}

# ── Summary table ─────────────────────────────────────────────────────
Header "RESULTS SUMMARY"
$results | Format-Table -AutoSize
Write-Host "`n  PASSED: $pass    FAILED: $fail" -ForegroundColor $(if ($fail -eq 0) {'Green'} else {'Yellow'})
Write-Host "`n  Dashboard : http://localhost:8888" -ForegroundColor Cyan
Write-Host "  Mitigations page: http://localhost:8888/mitigations" -ForegroundColor Cyan
Write-Host "  Flow tracker: http://localhost:8888/flow-tracker`n" -ForegroundColor Cyan
