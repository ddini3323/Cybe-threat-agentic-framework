$b = 'http://localhost:8888'

function Test($label, $method, $url, $body = $null) {
    try {
        if ($body) {
            $r = Invoke-RestMethod -Uri $url -Method $method -ContentType 'application/json' -Body $body -ErrorAction Stop
        } else {
            $r = Invoke-RestMethod -Uri $url -Method $method -ErrorAction Stop
        }
        Write-Host "  PASS  $label" -ForegroundColor Green
    } catch {
        Write-Host "  FAIL  $label  ->  $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n--- Core Endpoints ---" -ForegroundColor Yellow
Test 'GET  /api/health'           GET  "$b/api/health"
Test 'GET  /api/stats'            GET  "$b/api/stats"
Test 'GET  /api/events'           GET  "$b/api/events"
Test 'GET  /api/enriched-events'  GET  "$b/api/enriched-events"
Test 'GET  /api/patterns'         GET  "$b/api/patterns"
Test 'GET  /api/mitigations'      GET  "$b/api/mitigations"
Test 'GET  /api/pending'          GET  "$b/api/pending"
Test 'GET  /api/feeds'            GET  "$b/api/feeds"
Test 'GET  /api/logs'             GET  "$b/api/logs"
Test 'GET  /api/classifications'  GET  "$b/api/classifications"
Test 'GET  /api/benchmark'        GET  "$b/api/benchmark"

Write-Host "`n--- Ingest Endpoints ---" -ForegroundColor Yellow
Test 'POST /api/ingest/text' POST "$b/api/ingest/text" '{"text":"LockBit ransomware on 10.0.0.1 connecting to C2 185.220.101.47"}'
Test 'POST /api/ingest/json' POST "$b/api/ingest/json" '{"raw_text":"APT29 spear phishing campaign","indicator":"evil-domain.ru","source":"SIEM"}'
Test 'POST /api/ingest/csv'  POST "$b/api/ingest/csv"  '{"csv_data":"indicator,type,description\n1.2.3.4,IP,Malicious IP"}'

Write-Host "`n--- Chatbot /api/chat ---" -ForegroundColor Yellow
Test 'POST /api/chat  help'        POST "$b/api/chat" '{"message":"help"}'
Test 'POST /api/chat  queue'       POST "$b/api/chat" '{"message":"whats in the queue?"}'
Test 'POST /api/chat  running'     POST "$b/api/chat" '{"message":"whats running?"}'
Test 'POST /api/chat  complete'    POST "$b/api/chat" '{"message":"whats complete?"}'
Test 'POST /api/chat  patterns'    POST "$b/api/chat" '{"message":"show patterns"}'
Test 'POST /api/chat  mitigations' POST "$b/api/chat" '{"message":"show mitigations"}'
Test 'POST /api/chat  last'        POST "$b/api/chat" '{"message":"my last submission"}'

Write-Host "`n--- Pages (HTML) ---" -ForegroundColor Yellow
Test 'GET  /'             GET "$b/"
Test 'GET  /live-input'   GET "$b/live-input"
Test 'GET  /feeds'        GET "$b/feeds"
Test 'GET  /benchmark'    GET "$b/benchmark"
Test 'GET  /flow-tracker' GET "$b/flow-tracker"

Write-Host "`n--- Chat reply preview ---" -ForegroundColor Cyan
$r = Invoke-RestMethod -Uri "$b/api/chat" -Method POST -ContentType 'application/json' -Body '{"message":"whats running?"}'
Write-Host "  reply       : $($r.reply)"
Write-Host "  llm_available: $($r.llm_available)"
