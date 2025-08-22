"""
HTML template for the Threat Hunter dashboard.

This module exports a single constant, ``HTML_CONTENT``, which contains
the complete HTML, CSS and JavaScript used by the dashboard UI. The
content is stored as a raw string literal to preserve backslashes and
newlines exactly as defined in the original monolithic implementation.

Do not modify the contents of ``HTML_CONTENT`` unless you intend to
change the appearance or behaviour of the dashboard. All UI features
from the original script are preserved here.
"""

# NOTE: The HTML below is extremely lengthy because it includes the
# entire dashboard interface, modals, styles and client-side logic.
# It has been reproduced verbatim from the monolithic script provided
# by the user to ensure 1:1 functionality. Triple backticks used in
# code blocks within the JavaScript are safe inside this raw string.

HTML_CONTENT = r"""
<!DOCTYPE html>

<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wazuh Threat Hunter Pro (Gemini Edition)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            --card-bg: rgba(30, 41, 59, 0.8);
            --glass-bg: rgba(51, 65, 85, 0.1);
            --border-color: rgba(148, 163, 184, 0.2);
            --text-main: #f8fafc;
            --text-secondary: #cbd5e1;
            --accent-primary: #3b82f6;
            --accent-secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --critical: #dc2626;
        }

        body { 
            background: var(--bg-gradient);
            color: var(--text-main);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
        }
        
        .glass-card {
            background: var(--card-bg);
            backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid var(--border-color);
            border-radius: 1rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .glass-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
        }
        
        .severity-Critical { 
            border-left: 4px solid var(--critical);
            background: linear-gradient(90deg, rgba(220, 38, 38, 0.1) 0%, transparent 100%);
        }
        .severity-High { 
            border-left: 4px solid var(--danger);
            background: linear-gradient(90deg, rgba(239, 68, 68, 0.1) 0%, transparent 100%);
        }
        .severity-Medium { 
            border-left: 4px solid var(--warning);
            background: linear-gradient(90deg, rgba(245, 158, 11, 0.1) 0%, transparent 100%);
        }
        .severity-Low { 
            border-left: 4px solid var(--success);
            background: linear-gradient(90deg, rgba(16, 185, 129, 0.1) 0%, transparent 100%);
        }
        
        .modal-backdrop {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            display: none; align-items: center; justify-content: center; z-index: 1100;
            animation: fadeIn 0.2s ease-out;
        }
        
        .modal-content {
            background: var(--card-bg);
            backdrop-filter: blur(20px) saturate(180%);
            max-width: 90vw; width: 800px;
            max-height: 90vh; overflow-y: auto;
            border-radius: 1rem; padding: 2rem;
            border: 1px solid var(--border-color);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: slideUp 0.3s ease-out;
            margin: 1rem;
        }
        
        @media (max-width: 768px) {
            .modal-content {
                width: 95vw;
                max-width: 95vw;
                padding: 1rem;
                margin: 0.5rem;
                max-height: 95vh;
            }
            
            .modal-content h2 {
                font-size: 1.25rem;
            }
            
            .grid.grid-cols-1.md\:grid-cols-2.lg\:grid-cols-3 {
                grid-template-columns: 1fr !important;
            }
            
            .flex.flex-wrap.gap-3 {
                flex-direction: column;
                gap: 0.75rem;
            }
            
            .flex.flex-wrap.gap-3 > * {
                width: 100%;
            }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        @keyframes slideUp {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .chat-bubble { 
            max-width: 85%; padding: 1rem; border-radius: 1rem; margin-bottom: 0.75rem;
            animation: messageSlide 0.3s ease-out;
        }
        
        @keyframes messageSlide {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .chat-user { 
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            align-self: flex-end; margin-left: auto;
            color: white;
        }
        .chat-ai { 
            background: var(--glass-bg);
            border: 1px solid var(--border-color);
            align-self: flex-start;
        }
        
        .script-output { 
            background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem; 
            padding: 1.5rem; 
            font-family: 'JetBrains Mono', 'Consolas', 'Monaco', monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 0.875rem;
            line-height: 1.6;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
            border: none;
            color: white;
            font-weight: 600;
            padding: 0.75rem 1.5rem;
            border-radius: 0.75rem;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success), #059669);
            box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #dc2626);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, var(--warning), #d97706);
            box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
        }
        
        .loading-spinner {
            display: inline-block;
            width: 1rem;
            height: 1rem;
            border: 2px solid transparent;
            border-top: 2px solid currentColor;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .status-connected { 
            background: var(--success);
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);
        }
        .status-disconnected { 
            background: var(--danger);
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.5);
        }
        .status-connecting { 
            background: var(--warning);
            box-shadow: 0 0 10px rgba(245, 158, 11, 0.5);
        }
        
        .stat-card {
            text-align: center;
            padding: 1.5rem;
            border-radius: 1rem;
            background: var(--glass-bg);
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: scale(1.05);
            background: rgba(51, 65, 85, 0.2);
        }
        
        .issue-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }
        
        .action-btn {
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            border: none;
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .ignore-btn {
            background: linear-gradient(135deg, #6b7280, #4b5563);
            color: white;
        }
        
        .ignore-btn:hover {
            background: linear-gradient(135deg, #4b5563, #374151);
            transform: translateY(-1px);
        }
        
        .chat-btn {
            background: linear-gradient(135deg, var(--accent-primary), #2563eb);
            color: white;
        }
        
        .script-btn {
            background: linear-gradient(135deg, var(--success), #059669);
            color: white;
        }
        
        input[type="text"], input[type="number"] {
            background: rgba(51, 65, 85, 0.2);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            transition: all 0.3s ease;
        }
        
        input[type="text"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
            background: rgba(51, 65, 85, 0.3);
        }
        
        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 0.75rem;
            color: white;
            font-weight: 500;
            z-index: 1000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }
        
        .toast.show {
            transform: translateX(0);
        }
        
        .toast-success {
            background: linear-gradient(135deg, var(--success), #059669);
        }
        
        .toast-error {
            background: linear-gradient(135deg, var(--danger), #dc2626);
        }
        
        .log-button {
            background: linear-gradient(135deg, #475569, #334155);
            color: white;
            border: none;
            padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .log-button:hover {
            background: linear-gradient(135deg, #334155, #1e293b);
            transform: translateY(-1px);
        }
        
        .clickable-chart {
            cursor: pointer;
        }
        
        .clickable-chart:hover {
            transform: scale(1.02);
        }
    </style>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body class="p-4 sm:p-6 lg:p-8">

<div class="max-w-7xl mx-auto">
    <!-- Enhanced Header -->
    <header class="glass-card p-6 mb-8">
        <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
                <h1 class="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                    Wazuh Threat Hunter Pro
                </h1>
                <p class="text-sm text-gray-400 mt-1">
                    Gemini AI-Powered Security Analysis
                </p>
                <div class="flex flex-wrap gap-4 mt-2 text-sm">
                    <span class="flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full bg-blue-400"></div>
                        Last update: <span id="last-run" class="text-blue-300">Never</span>
                    </span>
                    <span class="flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full bg-purple-400"></div>
                        Active API Key: <span id="active-api-key" class="text-purple-300">Key 1</span>
                    </span>
                    <span class="flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full bg-green-400"></div>
                        Status: <span id="app-status" class="status-text">Initializing...</span>
                    </span>
                    <span class="flex items-center gap-2" id="countdown-container" style="display: none;">
                        <div class="w-2 h-2 rounded-full bg-yellow-400"></div>
                        Next scan in: <span id="countdown-timer" class="text-yellow-300 font-mono">--:--</span>
                    </span>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <button id="find-more-btn" class="btn-primary btn-success" title="Keyboard shortcut: Ctrl+F">
                    <span class="flex items-center gap-2">
                        Find More Issues (Ctrl+F)
                    </span>
                </button>
                <button id="help-btn" class="p-3 rounded-xl bg-blue-700/50 hover:bg-blue-600/50 transition-all duration-200" title="Keyboard shortcuts (Ctrl+H)">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </button>
                <button id="settings-btn" class="p-3 rounded-xl bg-gray-700/50 hover:bg-gray-600/50 transition-all duration-200" title="Settings (Ctrl+S)">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                    </svg>
                </button>
                <div id="status-indicator" class="w-4 h-4 rounded-full status-connecting animate-pulse" title="Connecting..."></div>
            </div>
        </div>
    </header>

    <!-- Enhanced AI Summary -->
    <div class="glass-card p-6 mb-8">
        <div class="flex items-center gap-3 mb-4">
            <div class="w-8 h-8 rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center text-white font-bold">
                🤖
            </div>
            <h2 class="text-xl font-semibold">Gemini AI Security Analysis</h2>
        </div>
        <p id="ai-summary" class="text-gray-300 leading-relaxed">Initializing AI analysis...</p>
    </div>

    <!-- Enhanced Main Grid -->
    <div class="grid grid-cols-1 xl:grid-cols-3 gap-8">
        
        <!-- Left Column: Issues -->
        <div class="xl:col-span-2 space-y-8">
            <!-- Security Issues Section -->
            <div class="glass-card p-6">
                <div class="flex items-center justify-between mb-6 security-issues-header p-2 -m-2" id="security-issues-header">
                    <h2 class="text-xl font-semibold flex items-center gap-2">
                        <span class="w-6 h-6 rounded bg-red-500/20 flex items-center justify-center text-red-400">🔒</span>
                        Security Issues
                        <span id="security-issue-count" class="px-2 py-1 bg-red-500/20 text-red-300 rounded-lg text-sm font-medium">0</span>
                    </h2>
                    <div class="flex items-center gap-2">
                        <div id="security-issues-loading" class="loading-spinner hidden text-blue-400"></div>
                        <span class="text-xs text-gray-500">Threats & Security</span>
                    </div>
                </div>
                
                <div id="security-issues-container" class="space-y-4 max-h-[350px] overflow-y-auto pr-2 custom-scrollbar">
                    <!-- Security issues will be injected here -->
                </div>
            </div>
            
            <!-- Operational Issues Section -->
            <div class="glass-card p-6">
                <div class="flex items-center justify-between mb-6 operational-issues-header p-2 -m-2" id="operational-issues-header">
                    <h2 class="text-xl font-semibold flex items-center gap-2">
                        <span class="w-6 h-6 rounded bg-yellow-500/20 flex items-center justify-center text-yellow-400">⚙️</span>
                        Operational Issues
                        <span id="operational-issue-count" class="px-2 py-1 bg-yellow-500/20 text-yellow-300 rounded-lg text-sm font-medium">0</span>
                    </h2>
                    <div class="flex items-center gap-2">
                        <div id="operational-issues-loading" class="loading-spinner hidden text-blue-400"></div>
                        <span class="text-xs text-gray-500">Performance & Health</span>
                    </div>
                </div>
                
                <div id="operational-issues-container" class="space-y-4 max-h-[350px] overflow-y-auto pr-2 custom-scrollbar">
                    <!-- Operational issues will be injected here -->
                </div>
            </div>
            
            <!-- Chat Section -->
            <div class="glass-card p-6">
                <div class="flex items-center gap-3 mb-4">
                    <div class="w-6 h-6 rounded bg-blue-500/20 flex items-center justify-center text-blue-400">💬</div>
                    <h2 class="text-xl font-semibold">Chat with AI Analyst</h2>
                </div>
                <div id="chat-container" class="max-h-[350px] overflow-y-auto mb-4 flex flex-col space-y-3 p-4 bg-black/20 rounded-xl border border-gray-700/50 custom-scrollbar">
                    <div class="chat-bubble chat-ai">
                        👋 Hello! I'm your AI security analyst. Ask me anything about your logs, threats, or security issues.
                    </div>
                </div>
                <div class="flex gap-3">
                    <input type="text" id="query-input" class="flex-1" placeholder="Ask about suspicious activities, specific IPs, timeframes...">
                    <button id="clear-chat-btn" class="btn-primary bg-gray-600 hover:bg-gray-700 px-4">
                        🗑️ Clear
                    </button>
                    <button id="query-btn" class="btn-primary px-6">
                        <span class="query-btn-text">Send</span>
                        <div class="loading-spinner hidden"></div>
                    </button>
                </div>
            </div>
        </div>

        <!-- Right Column: Stats & Visuals -->
        <div class="space-y-8">
            <!-- Enhanced Statistics -->
            <div class="glass-card p-6">
                <h2 class="text-xl font-semibold mb-6 flex items-center gap-2">
                    <span class="w-6 h-6 rounded bg-green-500/20 flex items-center justify-center text-green-400 text-xs font-bold">DB</span>
                    System Overview
                </h2>
                <div class="grid grid-cols-1 gap-4">
                    <div class="stat-card">
                        <div class="text-3xl font-bold text-blue-400" id="total-logs">0</div>
                        <div class="text-sm text-gray-400 mt-1">Total Logs Indexed</div>
                    </div>
                    <div class="stat-card">
                        <div class="text-3xl font-bold text-green-400" id="new-logs">0</div>
                        <div class="text-sm text-gray-400 mt-1">New Logs (Last Cycle)</div>
                    </div>
                    <div class="stat-card">
                        <div class="text-3xl font-bold text-red-400" id="anomalies">0</div>
                        <div class="text-sm text-gray-400 mt-1">Active Security Issues</div>
                    </div>
                </div>
            </div>
            
            <!-- Enhanced Charts -->
            <div class="glass-card p-6">
                <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                    <span class="w-5 h-5 rounded bg-purple-500/20 flex items-center justify-center text-purple-400">📈</span>
                    Log Activity (Last Hour)
                </h2>
                <div class="chart-container">
                    <canvas id="logTrendChart"></canvas>
                </div>
            </div>
            
            <div class="glass-card p-6 clickable-chart" id="rule-chart-card">
                <h2 class="text-lg font-semibold mb-4 flex items-center gap-2">
                    <span class="w-5 h-5 rounded bg-yellow-500/20 flex items-center justify-center text-yellow-400 text-xs font-bold">AI</span>
                    Top Security Rules
                    <span class="text-xs text-gray-500 ml-2">Click to expand</span>
                </h2>
                <div class="chart-container">
                    <canvas id="ruleDistChart"></canvas>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Toast Notifications -->
<div id="toast-container"></div>

<!-- Enhanced Modals -->
<!-- Log Detail Modal -->
<div id="log-modal" class="modal-backdrop">
    <div class="modal-content">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Log Details</h2>
            <button id="close-log-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        <pre id="log-content" class="script-output"></pre>
    </div>
</div>

<!-- Issue Chat Modal -->
<div id="issue-query-modal" class="modal-backdrop">
    <div class="modal-content">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Chat About Issue: <span id="issue-title" class="text-blue-400"></span></h2>
            <button id="close-issue-query-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        <div id="issue-chat-container" class="max-h-[400px] overflow-y-auto mb-6 flex flex-col space-y-3 p-4 bg-black/20 rounded-xl border border-gray-700/50 custom-scrollbar">
            <!-- Issue chat messages will be appended here -->
        </div>
        <div class="flex gap-3">
            <input type="text" id="issue-query-input" class="flex-1" placeholder="Ask a follow-up question...">
            <button id="issue-query-btn" class="btn-primary">Send</button>
        </div>
    </div>
</div>

<!-- Script Generation Modal -->
<div id="script-modal" class="modal-backdrop">
    <div class="modal-content">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Diagnosis & Repair Script: <span id="script-issue-title" class="text-green-400"></span></h2>
            <button id="close-script-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        <div id="script-content" class="script-output mb-6">
            <div class="flex items-center gap-2">
                <div class="loading-spinner"></div>
                Generating comprehensive diagnosis and repair script...
            </div>
        </div>
        <div class="flex gap-3">
            <button id="copy-script-btn" class="btn-primary btn-success">📋 Copy Script</button>
            <button id="download-script-btn" class="btn-primary">💾 Download Script</button>
        </div>
    </div>
</div>

<!-- Settings Modal -->
<div id="settings-modal" class="modal-backdrop">
    <div class="modal-content">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Configuration Settings</h2>
            <button id="close-settings-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        <form id="settings-form" class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Processing Interval (seconds)</label>
                    <input type="number" name="processing_interval" class="w-full">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Initial Scan Count</label>
                    <input type="number" name="initial_scan_count" class="w-full">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Log Batch Size</label>
                    <input type="number" name="log_batch_size" class="w-full">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Vector Search K (Query)</label>
                    <input type="number" name="search_k" class="w-full">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Vector Search K (Analysis)</label>
                    <input type="number" name="analysis_k" class="w-full">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Max Issues Displayed</label>
                    <input type="number" name="max_issues" class="w-full">
                </div>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Gemini Max Output Tokens</label>
                <input type="number" name="max_output_tokens" class="w-full">
            </div>
            <div class="flex gap-3 pt-4">
                <button type="submit" class="btn-primary">💾 Save Settings</button>
                <button type="button" id="clear-db-btn" class="btn-primary btn-danger">🗑️ Clear Database</button>
            </div>
        </form>
    </div>
</div>

<!-- Rule Analysis Modal -->
<div id="rule-analysis-modal" class="modal-backdrop">
    <div class="modal-content" style="max-width: 95vw; width: 1400px;">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Security Rules Analysis</h2>
            <button id="close-rule-analysis-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        
        <!-- Large Rule Chart -->
        <div class="glass-card p-6 mb-6">
            <h3 class="text-xl font-semibold mb-4">Rule Distribution</h3>
            <div id="modal-rule-chart-container" class="chart-container" style="height: 400px;">
                <canvas id="modalRuleChart"></canvas>
            </div>
        </div>
        
        <!-- Filtering Controls -->
        <div class="flex flex-wrap gap-3 mb-6 p-4 bg-black/20 rounded-lg border border-gray-700/50">
            <select id="rule-severity-filter" class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white">
                <option value="">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
            </select>
            <input type="text" id="rule-search-issues" placeholder="Search issues..." 
                   class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white flex-1 min-w-[200px]">
            <button id="rule-clear-filters" class="px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded text-white">
                Clear Filters
            </button>
            <div class="ml-auto">
                <span id="rule-filtered-count" class="text-gray-400"></span>
            </div>
        </div>
        
        <!-- Issues Container -->
        <div id="rule-issues-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[60vh] overflow-y-auto custom-scrollbar">
            <!-- Issues will be displayed here based on rule selection -->
        </div>
    </div>
</div>

<!-- Full Security Issues Modal -->
<div id="full-issues-modal" class="modal-backdrop">
    <div class="modal-content" style="max-width: 95vw; width: 1400px;">
        <div class="flex justify-between items-center mb-6">
            <h2 id="full-issues-modal-title" class="text-2xl font-bold">All Issues</h2>
            <button id="close-full-issues-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        
        <!-- Filtering Controls for Full Modal -->
        <div class="flex flex-wrap gap-3 mb-6 p-4 bg-black/20 rounded-lg border border-gray-700/50">
            <select id="modal-severity-filter" class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white">
                <option value="">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
            </select>
            <select id="modal-sort-issues" class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white">
                <option value="timestamp-desc">Newest First</option>
                <option value="timestamp-asc">Oldest First</option>
                <option value="severity-desc">Severity (High to Low)</option>
                <option value="severity-asc">Severity (Low to High)</option>
                <option value="title-asc">Title (A-Z)</option>
            </select>
            <input type="text" id="modal-search-issues" placeholder="Search issues..." 
                   class="bg-gray-800 border border-gray-600 rounded px-3 py-2 text-white flex-1 min-w-[200px]">
            <button id="modal-clear-filters" class="px-4 py-2 bg-gray-600 hover:bg-gray-500 rounded text-white">
                Clear Filters
            </button>
            <div class="ml-auto flex items-center gap-2">
                <button id="grid-view-btn" class="px-3 py-2 bg-blue-600 rounded text-white">Grid</button>
                <button id="list-view-btn" class="px-3 py-2 bg-gray-600 rounded text-white">List</button>
            </div>
        </div>
        
        <!-- Issues Container with Grid/List toggle -->
        <div id="full-issues-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[70vh] overflow-y-auto custom-scrollbar">
            <!-- All issues will be displayed here -->
        </div>
    </div>
</div>

<!-- Help Modal -->
<div id="help-modal" class="modal-backdrop">
    <div class="modal-content" style="max-width: 800px; width: 90vw;">
        <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Threat Hunter Pro - Power User Guide</h2>
            <button id="close-help-modal-btn" class="text-gray-400 hover:text-white text-2xl">×</button>
        </div>
        
        <div class="space-y-6">
            <div class="glass-card p-4">
                <h3 class="text-lg font-semibold mb-3 text-blue-400">Keyboard Shortcuts</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                    <div class="flex justify-between"><kbd class="bg-gray-700 px-2 py-1 rounded">Ctrl+F</kbd><span>Find More Issues</span></div>
                    <div class="flex justify-between"><kbd class="bg-gray-700 px-2 py-1 rounded">Ctrl+R</kbd><span>Refresh Data</span></div>
                    <div class="flex justify-between"><kbd class="bg-gray-700 px-2 py-1 rounded">Ctrl+S</kbd><span>Open Settings</span></div>
                    <div class="flex justify-between"><kbd class="bg-gray-700 px-2 py-1 rounded">Ctrl+C</kbd><span>Focus Chat Input</span></div>
                    <div class="flex justify-between"><kbd class="bg-gray-700 px-2 py-1 rounded">Ctrl+H</kbd><span>Show This Help</span></div>
                    <div class="flex justify-between"><kbd class="bg-gray-700 px-2 py-1 rounded">Esc</kbd><span>Close Modals</span></div>
                </div>
            </div>
            
            <div class="glass-card p-4">
                <h3 class="text-lg font-semibold mb-3 text-green-400">Professional Features</h3>
                <ul class="space-y-2 text-sm text-gray-300">
                    <li>• <strong>Advanced Issue Analysis:</strong> Enhanced AI detection with threat categorization</li>
                    <li>• <strong>Comprehensive Search:</strong> Multi-strategy log retrieval and correlation</li>
                    <li>• <strong>Professional Interface:</strong> Clean, production-ready design with power user shortcuts</li>
                    <li>• <strong>Real-time Monitoring:</strong> Continuous background analysis and alerting</li>
                    <li>• <strong>Export & Integration:</strong> API endpoints for external system integration</li>
                </ul>
            </div>
            
            <div class="glass-card p-4">
                <h3 class="text-lg font-semibold mb-3 text-orange-400">Quick Tips</h3>
                <ul class="space-y-2 text-sm text-gray-300">
                    <li>• Click on severity badges to filter issues</li>
                    <li>• Click chart cards to expand detailed views</li>
                    <li>• Use chat interface for contextual log analysis</li>
                    <li>• Generate automated remediation scripts for issues</li>
                    <li>• All data auto-refreshes every 15 seconds</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<style>
    .custom-scrollbar::-webkit-scrollbar {
        width: 6px;
    }
    .custom-scrollbar::-webkit-scrollbar-track {
        background: rgba(51, 65, 85, 0.1);
        border-radius: 3px;
    }
    .custom-scrollbar::-webkit-scrollbar-thumb {
        background: rgba(148, 163, 184, 0.3);
        border-radius: 3px;
    }
    .custom-scrollbar::-webkit-scrollbar-thumb:hover {
        background: rgba(148, 163, 184, 0.5);
    }
    
    /* Line clamp utility for grid view */
    .line-clamp-3 {
        display: -webkit-box;
        -webkit-line-clamp: 3;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }
    
    /* Fix chart sizing issues */
    #logTrendChart, #ruleDistChart {
        max-height: 200px !important;
        height: 200px !important;
    }
    
    #modalRuleChart {
        max-height: 400px !important;
        height: 400px !important;
    }
    
    .chart-container {
        position: relative;
        height: 200px !important;
        max-height: 200px !important;
        width: 100%;
        overflow: hidden;
    }
    
    #modal-rule-chart-container {
        height: 400px !important;
        max-height: 400px !important;
    }
    
    /* Clickable issues headers */
    .security-issues-header, .operational-issues-header {
        cursor: pointer;
        transition: all 0.2s ease;
    }
    
    .security-issues-header:hover {
        transform: translateY(-1px);
        background: rgba(239, 68, 68, 0.1);
        border-radius: 0.5rem;
    }
    
    .operational-issues-header:hover {
        transform: translateY(-1px);
        background: rgba(245, 158, 11, 0.1);
        border-radius: 0.5rem;
    }
    
    /* Application status styles */
    .status-text {
        font-size: 0.875rem;
        color: #94a3b8;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    /* Additional responsive improvements */
    @media (max-width: 1024px) {
        .xl\:col-span-2 {
            grid-column: span 1 !important;
        }
        
        .grid.grid-cols-1.xl\:grid-cols-3 {
            grid-template-columns: 1fr !important;
        }
    }
    
    @media (max-width: 640px) {
        body {
            padding: 0.5rem;
        }
        
        .max-w-7xl {
            max-width: 100%;
        }
        
        .text-3xl {
            font-size: 1.5rem;
        }
        
        .p-6 {
            padding: 1rem;
        }
        
        .gap-8 {
            gap: 1rem;
        }
        
        .flex.flex-col.sm\:flex-row {
            flex-direction: column !important;
            gap: 1rem;
        }
        
        .issue-actions {
            flex-direction: column;
        }
        
        .issue-actions .action-btn {
            width: 100%;
            text-align: center;
        }
    }
    
    /* Ensure charts are responsive */
    .chart-container canvas {
        max-width: 100% !important;
        height: auto !important;
    }
    
    /* Improved scrollbar for mobile */
    @media (max-width: 768px) {
        .custom-scrollbar::-webkit-scrollbar {
            width: 3px;
        }
    }
</style>

<script>
    // Enhanced JavaScript with better UX
    let logTrendChart, ruleDistChart, modalRuleChart;
    let currentIssueId = null;
    let issueChatHistory = [];
    let chatHistory = [];
    let countdownInterval = null;
    let lastUpdateTime = null;
    let processingInterval = 600; // Default 10 minutes
    let allIssues = []; // Store all issues for filtering
    let isGridView = true;
    let selectedRuleFilter = null;
    let dashboard_data = {};

    // Utility Functions
    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => document.body.removeChild(toast), 300);
        }, 3000);
    }

    function renderMarkdown(text) {
        if (!text || typeof text !== 'string') return '';
        
        // Simple markdown rendering for basic formatting
        return text
            // Bold text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            // Italic text  
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            // Inline code
            .replace(/`(.*?)`/g, '<code class="bg-gray-700 px-1 py-0.5 rounded text-sm">$1</code>')
            // Code blocks
            .replace(/```(.*?)```/gs, '<pre class="bg-gray-800 p-3 rounded mt-2 mb-2 overflow-x-auto"><code>$1</code></pre>')
            // Line breaks
            .replace(/\n/g, '<br>');
    }

    function startCountdownTimer() {
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
        
        const updateCountdown = () => {
            if (!lastUpdateTime) {
                console.log('No lastUpdateTime set for countdown');
                return;
            }
            
            const now = Date.now();
            const nextScan = lastUpdateTime + (processingInterval * 1000);
            const timeLeft = Math.max(0, nextScan - now);
            
            console.log('Countdown debug:', {
                lastUpdateTime: new Date(lastUpdateTime),
                processingInterval,
                nextScan: new Date(nextScan),
                timeLeft: Math.floor(timeLeft / 1000) + 's'
            });
            
            if (timeLeft === 0) {
                document.getElementById('countdown-container').style.display = 'none';
                return;
            }
            
            const minutes = Math.floor(timeLeft / 60000);
            const seconds = Math.floor((timeLeft % 60000) / 1000);
            
            document.getElementById('countdown-timer').textContent = 
                `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            document.getElementById('countdown-container').style.display = 'flex';
        };
        
        updateCountdown();
        countdownInterval = setInterval(updateCountdown, 1000);
    }

    function setLoadingState(button, isLoading, originalText) {
        const spinner = button.querySelector('.loading-spinner');
        const text = button.querySelector('.query-btn-text') || button;
        
        if (isLoading) {
            button.disabled = true;
            if (spinner) spinner.classList.remove('hidden');
            if (text !== button) text.textContent = 'Thinking...';
            else button.innerHTML = '<div class="loading-spinner"></div>';
        } else {
            button.disabled = false;
            if (spinner) spinner.classList.add('hidden');
            if (text !== button) text.textContent = originalText;
            else button.textContent = originalText;
        }
    }

    function initializeCharts() {
        const logTrendCanvas = document.getElementById('logTrendChart');
        const ruleDistCanvas = document.getElementById('ruleDistChart');
        
        if (!logTrendCanvas || !ruleDistCanvas) {
            console.error('Chart canvas elements not found');
            return;
        }
        
        const chartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { 
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(30, 41, 59, 0.9)',
                    titleColor: '#f8fafc',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(148, 163, 184, 0.2)',
                    borderWidth: 1,
                    cornerRadius: 8,
                }
            },
            scales: {
                x: { 
                    ticks: { color: '#94a3b8' }, 
                    grid: { color: 'rgba(148, 163, 184, 0.1)' },
                    border: { color: 'rgba(148, 163, 184, 0.2)' }
                },
                y: { 
                    ticks: { color: '#94a3b8' }, 
                    grid: { color: 'rgba(148, 163, 184, 0.1)' },
                    border: { color: 'rgba(148, 163, 184, 0.2)' }
                }
            }
        };

        try {
            const trendCtx = logTrendCanvas.getContext('2d');
            logTrendChart = new Chart(trendCtx, {
                type: 'line',
                data: { 
                    labels: [], 
                    datasets: [{ 
                        label: 'Logs per Minute', 
                        data: [], 
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4,
                        fill: true,
                        pointBackgroundColor: '#3b82f6',
                        pointBorderColor: '#1e40af',
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }] 
                },
                options: { 
                    ...chartOptions,
                    height: 200,
                    scales: { 
                        ...chartOptions.scales, 
                        x: { 
                            ...chartOptions.scales.x,
                            type: 'category'  // Changed from 'time' to fix display issues
                        } 
                    } 
                }
            });
            console.log('Log trend chart initialized');
        } catch (error) {
            console.error('Error initializing log trend chart:', error);
        }

        try {
            const ruleCtx = ruleDistCanvas.getContext('2d');
            ruleDistChart = new Chart(ruleCtx, {
                type: 'doughnut',
                data: { 
                    labels: [], 
                    datasets: [{ 
                        label: 'Rule Events', 
                        data: [], 
                        backgroundColor: [
                            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                            '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1'
                        ],
                        borderWidth: 2,
                        borderColor: 'rgba(30, 41, 59, 0.8)'
                    }] 
                },
                options: { 
                    ...chartOptions,
                    height: 200,
                    onClick: (event, elements) => {
                        if (elements.length > 0) {
                            const index = elements[0].index;
                            const ruleName = ruleDistChart.data.labels[index];
                            openRuleAnalysisModal(ruleName);
                        }
                    },
                    plugins: { 
                        legend: { 
                            position: 'bottom', 
                            labels: { 
                                color: '#cbd5e1',
                                usePointStyle: true,
                                padding: 15,
                                font: { size: 11 }
                            } 
                        },
                        tooltip: {
                            backgroundColor: 'rgba(30, 41, 59, 0.9)',
                            titleColor: '#f8fafc',
                            bodyColor: '#cbd5e1',
                            borderColor: 'rgba(148, 163, 184, 0.2)',
                            borderWidth: 1,
                            cornerRadius: 8,
                            callbacks: {
                                afterLabel: function(context) {
                                    return 'Click to view details';
                                }
                            }
                        }
                    } 
                }
            });
            console.log('Rule distribution chart initialized');
        } catch (error) {
            console.error('Error initializing rule distribution chart:', error);
        }
    }

    function openRuleAnalysisModal(selectedRule = null) {
        const modal = document.getElementById('rule-analysis-modal');
        selectedRuleFilter = selectedRule;
        
        // Update the large chart in the modal
        updateRuleAnalysisModal();
        
        modal.style.display = 'flex';
    }

    function updateRuleAnalysisModal() {
        const container = document.getElementById('rule-issues-container');
        
        // Initialize or update the large chart
        if (!modalRuleChart) {
            const ctx = document.getElementById('modalRuleChart').getContext('2d');
            
            modalRuleChart = new Chart(ctx, {
                type: 'doughnut',
                data: { 
                    labels: [], 
                    datasets: [{ 
                        label: 'Rule Events', 
                        data: [], 
                        backgroundColor: [
                            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                            '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1',
                            '#14b8a6', '#a855f7', '#f59e0b', '#ef4444', '#3b82f6'
                        ],
                        borderWidth: 2,
                        borderColor: 'rgba(30, 41, 59, 0.8)'
                    }] 
                },
                options: { 
                    responsive: true,
                    maintainAspectRatio: false,
                    height: 400,
                    onClick: (event, elements) => {
                        if (elements.length > 0) {
                            const index = elements[0].index;
                            const ruleName = modalRuleChart.data.labels[index];
                            selectedRuleFilter = ruleName;
                            filterRuleIssues();
                        }
                    },
                    plugins: { 
                        legend: { 
                            position: 'bottom', 
                            labels: { 
                                color: '#cbd5e1',
                                usePointStyle: true,
                                padding: 15,
                                font: { size: 12 }
                            } 
                        },
                        tooltip: {
                            backgroundColor: 'rgba(30, 41, 59, 0.9)',
                            titleColor: '#f8fafc',
                            bodyColor: '#cbd5e1',
                            borderColor: 'rgba(148, 163, 184, 0.2)',
                            borderWidth: 1,
                            cornerRadius: 8,
                            callbacks: {
                                afterLabel: function(context) {
                                    return 'Click to filter issues by this rule';
                                }
                            }
                        }
                    } 
                }
            });
        }
        
        // Update chart data
        const ruleData = dashboard_data.rule_distribution || {};
        const sortedRules = Object.entries(ruleData)
            .sort(([,a],[,b]) => b-a)
            .slice(0, 15); // Show top 15 in the modal
        
        modalRuleChart.data.labels = sortedRules.map(([rule]) => rule);
        modalRuleChart.data.datasets[0].data = sortedRules.map(([,count]) => count);
        modalRuleChart.update();
        
        // Filter issues based on selected rule
        filterRuleIssues();
    }

    function filterRuleIssues() {
        const severityFilter = document.getElementById('rule-severity-filter').value;
        const searchTerm = document.getElementById('rule-search-issues').value.toLowerCase();
        const container = document.getElementById('rule-issues-container');
        
        let filteredIssues = [...allIssues];
        
        // Filter by rule if one is selected
        if (selectedRuleFilter) {
            filteredIssues = filteredIssues.filter(issue => {
                return issue.summary.toLowerCase().includes(selectedRuleFilter.toLowerCase()) ||
                       issue.title.toLowerCase().includes(selectedRuleFilter.toLowerCase()) ||
                       issue.recommendation.toLowerCase().includes(selectedRuleFilter.toLowerCase());
            });
        }
        
        // Apply severity filter
        if (severityFilter) {
            filteredIssues = filteredIssues.filter(issue => issue.severity === severityFilter);
        }
        
        // Apply search filter
        if (searchTerm) {
            filteredIssues = filteredIssues.filter(issue => 
                issue.title.toLowerCase().includes(searchTerm) ||
                issue.summary.toLowerCase().includes(searchTerm)
            );
        }
        
        // Update counter
        document.getElementById('rule-filtered-count').textContent = 
            `Showing ${filteredIssues.length} of ${allIssues.length} issues`;
        
        // Display issues
        displayRuleIssues(filteredIssues);
    }

    function displayRuleIssues(issues) {
        const container = document.getElementById('rule-issues-container');
        container.innerHTML = '';
        
        if (issues.length === 0) {
            container.innerHTML = `
                <div class="col-span-full text-center py-12">
                    <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-blue-500/20 flex items-center justify-center">
                        <span class="text-2xl">SEARCH</span>
                    </div>
                    <p class="text-gray-400 text-lg">${selectedRuleFilter ? `No issues found for rule: ${selectedRuleFilter}` : 'No issues match your filters'}</p>
                    <p class="text-gray-500 text-sm mt-2">Try adjusting your search criteria</p>
                </div>
            `;
            return;
        }

        issues.forEach((issue, index) => {
            const issueEl = document.createElement('div');
            issueEl.className = `glass-card p-4 severity-${issue.severity} h-fit`;
            
            const severityIcons = {
                'Critical': 'CRIT',
                'High': 'HIGH',
                'Medium': 'MED',
                'Low': 'LOW'
            };
            
            const severityColors = {
                'Critical': 'text-red-400 bg-red-500/20',
                'High': 'text-orange-400 bg-orange-500/20',
                'Medium': 'text-yellow-400 bg-yellow-500/20',
                'Low': 'text-green-400 bg-green-500/20'
            };

            const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                ? issue.related_logs.slice(0, 3).map(logId => 
                    `<button class="log-button text-xs" data-log-id="${logId}" title="Click to view log details">
                        ${logId.substring(0, 6)}...
                    </button>`
                  ).join('')
                : '<span class="text-gray-500 text-xs">No logs</span>';

            issueEl.innerHTML = `
                <div class="flex justify-between items-start mb-3">
                    <div class="flex items-center gap-2">
                        <div class="w-6 h-6 rounded ${severityColors[issue.severity]} flex items-center justify-center text-sm">
                            ${severityIcons[issue.severity]}
                        </div>
                        <div>
                            <span class="text-xs font-bold uppercase ${severityColors[issue.severity].split(' ')[0]} block">
                                ${issue.severity}
                            </span>
                            <h3 class="font-bold text-sm text-white leading-tight">${issue.title}</h3>
                        </div>
                    </div>
                    <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                        ${new Date(issue.timestamp).toLocaleTimeString()}
                    </span>
                </div>
                
                <div class="text-gray-300 mb-3 text-sm leading-relaxed line-clamp-3">${renderMarkdown(issue.summary)}</div>
                
                <details class="mb-3">
                    <summary class="cursor-pointer text-blue-400 hover:text-blue-300 text-sm mb-2">
                        📋 Details & Logs
                    </summary>
                    <div class="mt-2 p-3 bg-black/20 rounded border border-gray-700/50">
                        <div class="mb-3">
                            <h4 class="font-semibold text-white text-sm mb-1"> Actions:</h4>
                            <div class="text-gray-300 text-sm">${renderMarkdown(issue.recommendation.substring(0, 200))}${issue.recommendation.length > 200 ? '...' : ''}</div>
                        </div>
                        <div>
                            <h4 class="font-semibold text-white text-sm mb-1">📄 Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                            <div class="flex flex-wrap gap-1">
                                ${relatedLogsHtml}
                            </div>
                        </div>
                    </div>
                </details>
                
                <div class="flex gap-1 flex-wrap">
                    <button class="action-btn ignore-btn text-xs py-1 px-2" data-issue-id="${issue.id}">
                        🗑️ Ignore
                    </button>
                    <button class="action-btn chat-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${issue.title}">
                        💬 Chat
                    </button>
                    <button class="action-btn script-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${issue.title}">
                        🔧 Script
                    </button>
                </div>
            `;
            container.appendChild(issueEl);
        });
    }

    async function updateUI(data) {
        dashboard_data = data;
        
        // Update header info
        document.getElementById('last-run').textContent = data.last_run ? 
            new Date(data.last_run).toLocaleString() : 'Never';
        document.getElementById('ai-summary').innerHTML = renderMarkdown(data.summary);
        document.getElementById('active-api-key').textContent = `Key ${(data.active_api_key_index || 0) + 1}`;
        
        // Update application status and handle countdown
        const status = data.status || 'Unknown';
        document.getElementById('app-status').textContent = status;
        
        // Update processing interval and start countdown if idle/ready
        if (data.settings && data.settings.processing_interval) {
            console.log('Updating processingInterval from', processingInterval, 'to', data.settings.processing_interval);
            processingInterval = data.settings.processing_interval;
        }
        
        if (data.last_run) {
            const newLastUpdateTime = new Date(data.last_run).getTime();
            console.log('Setting lastUpdateTime to', new Date(data.last_run), 'with processing interval', processingInterval);
            lastUpdateTime = newLastUpdateTime;
            if (status === 'Ready' || status === 'Idle') {
                startCountdownTimer();
            } else {
                document.getElementById('countdown-container').style.display = 'none';
            }
        }
        
        // Store all issues for filtering
        allIssues = data.issues || [];
        
        // Update statistics with animations
        updateStatWithAnimation('total-logs', data.stats.total_logs);
        updateStatWithAnimation('new-logs', data.stats.new_logs);
        updateStatWithAnimation('anomalies', data.stats.anomalies);
        
        // Separate issues by category
        const securityIssues = allIssues.filter(issue => issue.category === 'security').sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        const operationalIssues = allIssues.filter(issue => issue.category === 'operational').sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        // Update both issue displays
        updateSecurityIssuesDisplay(securityIssues);
        updateOperationalIssuesDisplay(operationalIssues);
        
        // Update charts
        updateCharts(data);
    }

    function updateStatWithAnimation(elementId, newValue) {
        const element = document.getElementById(elementId);
        const currentValue = parseInt(element.textContent.replace(/,/g, '')) || 0;
        
        if (currentValue !== newValue) {
            element.style.transform = 'scale(1.1)';
            setTimeout(() => {
                element.textContent = newValue.toLocaleString();
                element.style.transform = 'scale(1)';
            }, 150);
        }
    }

    function updateIssuesDisplay(issues, showFilters = true) {
        const container = document.getElementById('issues-container');
        
        if (!container) {
            console.error('Issues container not found');
            return;
        }
        
        container.innerHTML = '';
        
        if (!issues || issues.length === 0) {
            container.innerHTML = `
                <div class="text-center py-12">
                    <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                        <span class="text-2xl">OK</span>
                    </div>
                    <p class="text-gray-400 text-lg">No security issues found</p>
                    <p class="text-gray-500 text-sm mt-2">Your systems appear secure</p>
                </div>
            `;
            return;
        }
        
        console.log(`Displaying ${issues.length} issues in main widget`);
        
        // Update issue count
        const issueCountElement = document.getElementById('issue-count');
        if (issueCountElement) {
            issueCountElement.textContent = issues.length;
        }
        
        issues.forEach((issue, index) => {
            try {
                const issueEl = document.createElement('div');
                issueEl.className = `glass-card p-6 severity-${issue.severity || 'Low'}`;
                issueEl.style.animationDelay = `${index * 0.1}s`;
                
                const severityIcons = {
                    'Critical': 'CRIT',
                    'High': 'HIGH',
                    'Medium': 'MED',
                    'Low': 'LOW'
                };
                
                const severityColors = {
                    'Critical': 'text-red-400 bg-red-500/20',
                    'High': 'text-orange-400 bg-orange-500/20',
                    'Medium': 'text-yellow-400 bg-yellow-500/20',
                    'Low': 'text-green-400 bg-green-500/20'
                };
                
                // Format related logs with proper display - Fixed to ensure logs are shown
                const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                    ? issue.related_logs.map((logId, idx) => {
                        // Handle both string IDs and objects
                        const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                        return `<button class="log-button" data-log-id="${actualLogId}" title="Click to view log details">
                            Log ${idx + 1}: ${actualLogId.substring(0, 8)}...
                        </button>`;
                      }).join('')
                    : '<span class="text-gray-500 text-sm">No related logs available</span>';
                
                const severity = issue.severity || 'Low';
                const title = escapeHtml(issue.title || 'Untitled Issue');
                const summary = issue.summary || 'No summary available';
                const recommendation = issue.recommendation || 'No recommendations available';
                const timestamp = issue.timestamp ? new Date(issue.timestamp).toLocaleTimeString() : 'Unknown time';
                
                issueEl.innerHTML = `
                    <div class="flex justify-between items-start mb-4">
                        <div class="flex items-center gap-3">
                            <div class="w-8 h-8 rounded-lg ${severityColors[severity]} flex items-center justify-center">
                                ${severityIcons[severity]}
                            </div>
                            <div>
                                <span class="text-xs font-bold uppercase ${severityColors[severity].split(' ')[0]} block mb-1">
                                    ${severity} Severity
                                </span>
                                <h3 class="font-bold text-lg text-white">${title}</h3>
                            </div>
                        </div>
                        <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                            ${timestamp}
                        </span>
                    </div>
                    
                    <div class="text-gray-300 mb-4 leading-relaxed">${renderMarkdown(summary)}</div>
                    
                    <details class="mb-4">
                        <summary class="cursor-pointer text-blue-400 hover:text-blue-300 font-medium mb-2" onclick="event.stopPropagation();">
                            📋 View Recommendations & Related Logs
                        </summary>
                        <div class="mt-3 p-4 bg-black/20 rounded-lg border border-gray-700/50" onclick="event.stopPropagation();">
                            <div class="mb-4">
                                <h4 class="font-semibold text-white mb-2"> Recommended Actions:</h4>
                                <div class="text-gray-300 whitespace-pre-wrap leading-relaxed">${renderMarkdown(recommendation)}</div>
                            </div>
                            <div>
                                <h4 class="font-semibold text-white mb-2">📄 Related Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                                <div class="flex flex-wrap gap-2">
                                    ${relatedLogsHtml}
                                </div>
                            </div>
                        </div>
                    </details>
                    
                    <div class="issue-actions">
                        <button class="action-btn ignore-btn" data-issue-id="${issue.id || ''}">
                            🗑️ Ignore Issue
                        </button>
                        <button class="action-btn chat-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                            💬 Chat About This
                        </button>
                        <button class="action-btn script-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                            🔧 Generate Fix Script
                        </button>
                    </div>
                `;
                container.appendChild(issueEl);
            } catch (error) {
                console.error(`Error rendering issue ${index}:`, error, issue);
            }
        });
        
        // Update issue count to show total issues
        const countElement = document.getElementById('issue-count');
        if (countElement) {
            countElement.textContent = allIssues.length;
        }
    }

    function updateSecurityIssuesDisplay(issues) {
        const container = document.getElementById('security-issues-container');
        const countElement = document.getElementById('security-issue-count');
        
        if (!container) {
            console.error('Security issues container not found');
            return;
        }
        
        container.innerHTML = '';
        countElement.textContent = issues.length;
        
        if (!issues || issues.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-green-500/20 flex items-center justify-center">
                        <span class="text-xl">🔒</span>
                    </div>
                    <p class="text-gray-400">No security issues found</p>
                    <p class="text-gray-500 text-sm mt-1">Systems appear secure</p>
                </div>
            `;
            return;
        }
        
        issues.forEach((issue, index) => {
            container.appendChild(createIssueElement(issue, index));
        });
    }
    
    function updateOperationalIssuesDisplay(issues) {
        const container = document.getElementById('operational-issues-container');
        const countElement = document.getElementById('operational-issue-count');
        
        if (!container) {
            console.error('Operational issues container not found');
            return;
        }
        
        container.innerHTML = '';
        countElement.textContent = issues.length;
        
        if (!issues || issues.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <div class="w-12 h-12 mx-auto mb-3 rounded-full bg-green-500/20 flex items-center justify-center">
                        <span class="text-xl">⚙️</span>
                    </div>
                    <p class="text-gray-400">No operational issues found</p>
                    <p class="text-gray-500 text-sm mt-1">Systems running smoothly</p>
                </div>
            `;
            return;
        }
        
        issues.forEach((issue, index) => {
            container.appendChild(createIssueElement(issue, index));
        });
    }
    
    function createIssueElement(issue, index) {
        const issueEl = document.createElement('div');
        issueEl.className = `glass-card p-4 severity-${issue.severity || 'Low'}`;
        issueEl.style.animationDelay = `${index * 0.1}s`;
        
        const severityIcons = {
            'Critical': 'CRIT',
            'High': 'HIGH',
            'Medium': 'MED',
            'Low': 'LOW'
        };
        
        const severityColors = {
            'Critical': 'text-red-400 bg-red-500/20',
            'High': 'text-orange-400 bg-orange-500/20',
            'Medium': 'text-yellow-400 bg-yellow-500/20',
            'Low': 'text-green-400 bg-green-500/20'
        };
        
        const categoryIcons = {
            'security': '🔒',
            'operational': '⚙️'
        };
        
        // Format related logs
        const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
            ? issue.related_logs.map((logId, idx) => {
                const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                return `<button class="log-button" data-log-id="${actualLogId}" title="Click to view log details">
                    Log ${idx + 1}: ${actualLogId.substring(0, 8)}...
                </button>`;
              }).join('')
            : '<span class="text-gray-500 text-sm">No related logs available</span>';
        
        const severity = issue.severity || 'Low';
        const title = escapeHtml(issue.title || 'Untitled Issue');
        const summary = issue.summary || 'No summary available';
        const recommendation = issue.recommendation || 'No recommendations available';
        const category = issue.category || 'security';
        
        issueEl.innerHTML = `
            <div class="issue-header">
                <div class="flex items-start justify-between">
                    <div class="flex items-center gap-3">
                        <span class="text-2xl">${categoryIcons[category] || '🔒'}</span>
                        <div>
                            <h3 class="font-semibold text-lg text-gray-100 leading-tight">${title}</h3>
                            <span class="inline-flex items-center px-2 py-1 rounded-lg text-xs font-medium ${severityColors[severity]}">
                                ${severityIcons[severity]} ${severity}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            
            <details class="mt-4">
                <summary class="cursor-pointer text-blue-400 hover:text-blue-300 font-medium">
                    View Details & Actions
                </summary>
                <div class="mt-4 space-y-4">
                    <div>
                        <h4 class="font-medium text-gray-300 mb-2">Summary</h4>
                        <p class="text-gray-400 text-sm leading-relaxed">${summary}</p>
                    </div>
                    <div>
                        <h4 class="font-medium text-gray-300 mb-2">Recommendations</h4>
                        <p class="text-gray-400 text-sm leading-relaxed whitespace-pre-line">${recommendation}</p>
                    </div>
                    <div>
                        <h4 class="font-medium text-gray-300 mb-2">Related Logs</h4>
                        <div class="space-y-2">
                            ${relatedLogsHtml}
                        </div>
                    </div>
                </div>
            </details>
            
            <div class="issue-actions mt-4">
                <button class="action-btn ignore-btn" data-issue-id="${issue.id || ''}">
                    🗑️ Ignore
                </button>
                <button class="action-btn chat-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                    💬 Chat
                </button>
                <button class="action-btn script-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                    🔧 Fix Script
                </button>
            </div>
        `;
        
        return issueEl;
    }

    function updateCharts(data) {
        // Update trend chart with proper data formatting
        if (data.log_trend && data.log_trend.length > 0) {
            const trendLabels = data.log_trend.map(d => d.time);
            const trendData = data.log_trend.map(d => d.count);
            
            logTrendChart.data.labels = trendLabels;
            logTrendChart.data.datasets[0].data = trendData;
        } else {
            // Show empty state with sample data points
            logTrendChart.data.labels = ['Now-60min', 'Now-45min', 'Now-30min', 'Now-15min', 'Now'];
            logTrendChart.data.datasets[0].data = [0, 0, 0, 0, 0];
        }
        
        logTrendChart.options.maintainAspectRatio = false;
        logTrendChart.options.responsive = true;
        logTrendChart.update('none');

        // Update rule distribution chart with bounds checking
        if (data.rule_distribution && Object.keys(data.rule_distribution).length > 0) {
            const sortedRules = Object.entries(data.rule_distribution)
                .sort(([,a],[,b]) => b-a)
;
            
            ruleDistChart.data.labels = sortedRules.map(([rule]) => 
                rule.length > 30 ? rule.substring(0, 27) + '...' : rule
            );
            ruleDistChart.data.datasets[0].data = sortedRules.map(([,count]) => count);
        } else {
            // Show empty state
            ruleDistChart.data.labels = ['No data available'];
            ruleDistChart.data.datasets[0].data = [1];
        }
        
        ruleDistChart.options.maintainAspectRatio = false;
        ruleDistChart.options.responsive = true;
        ruleDistChart.update('none');
        
        // Update modal chart if it exists
        if (modalRuleChart) {
            updateRuleAnalysisModal();
        }
    }

    async function fetchData() {
        const statusIndicator = document.getElementById('status-indicator');
        
        try {
            console.log('Fetching dashboard data...');
            statusIndicator.className = 'w-4 h-4 rounded-full status-connecting animate-pulse';
            statusIndicator.title = 'Connecting...';
            
            const response = await fetch('/api/dashboard');
            console.log('Dashboard API response status:', response.status);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Dashboard data received:', {
                issueCount: data.issues ? data.issues.length : 0,
                totalLogs: data.stats ? data.stats.total_logs : 0,
                status: data.status
            });
            
            await updateUI(data);
            statusIndicator.className = 'w-4 h-4 rounded-full status-connected';
            statusIndicator.title = `Connected. Last update: ${new Date(data.last_run || Date.now()).toLocaleString()}`;
            
        } catch (error) {
            console.error("Failed to fetch dashboard data:", error);
            
            // Update UI with error state
            document.getElementById('ai-summary').textContent = 'Error: Could not connect to the backend service. Please check if the server is running.';
            statusIndicator.className = 'w-4 h-4 rounded-full status-disconnected';
            statusIndicator.title = `Connection failed: ${error.message}`;
            
            // Show error in issues container
            const issuesContainer = document.getElementById('issues-container');
            if (issuesContainer) {
                issuesContainer.innerHTML = `
                    <div class="text-center py-12">
                        <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/20 flex items-center justify-center">
                            <span class="text-2xl">❌</span>
                        </div>
                        <p class="text-red-400 text-lg">Connection Failed</p>
                        <p class="text-gray-500 text-sm mt-2">Unable to fetch security data from server</p>
                        <button onclick="fetchData()" class="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                            Retry Connection
                        </button>
                    </div>
                `;
            }
            
            showToast('Failed to fetch dashboard data. Check console for details.', 'error');
        }
    }

    async function triggerAnalysis() {
        const btn = document.getElementById('find-more-btn');
        const originalText = btn.textContent;
        
        try {
            setLoadingState(btn, true, originalText);
            document.getElementById('issues-loading').classList.remove('hidden');
            
            const response = await fetch('/api/analyze', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to trigger analysis');
            
            showToast('Analysis triggered successfully!');
            fetchData();
        } catch (error) {
            console.error("Failed to trigger analysis:", error);
            showToast('Failed to trigger analysis', 'error');
        } finally {
            setLoadingState(btn, false, 'SEARCH Find More Issues');
            document.getElementById('issues-loading').classList.add('hidden');
        }
    }

    async function ignoreIssue(issueId) {
        try {
            const response = await fetch(`/api/issues/${issueId}/ignore`, { method: 'POST' });
            if (!response.ok) throw new Error('Failed to ignore issue');
            
            showToast('Issue ignored successfully');
            fetchData();
        } catch (error) {
            console.error("Failed to ignore issue:", error);
            showToast('Failed to ignore issue', 'error');
        }
    }

    async function openIssueQueryModal(issueId, issueTitle) {
        currentIssueId = issueId;
        issueChatHistory = [];
        document.getElementById('issue-title').textContent = issueTitle;
        const issueChatContainer = document.getElementById('issue-chat-container');
        issueChatContainer.innerHTML = `
            <div class="chat-bubble chat-ai">
                👋 I'm here to help you understand and resolve this security issue. What would you like to know?
            </div>
        `;
        document.getElementById('issue-query-modal').style.display = 'flex';
        document.getElementById('issue-query-input').focus();
    }

    async function handleIssueQuery() {
        const query = document.getElementById('issue-query-input').value.trim();
        if (!query || !currentIssueId) return;
        
        const btn = document.getElementById('issue-query-btn');
        const issueChatContainer = document.getElementById('issue-chat-container');
        
        appendChatMessage(issueChatContainer, query, 'chat-user');
        document.getElementById('issue-query-input').value = '';
        
        setLoadingState(btn, true, 'Send');
        
        try {
            const response = await fetch(`/api/issues/${currentIssueId}/query`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query, history: issueChatHistory })
            });
            const result = await response.json();
            appendChatMessage(issueChatContainer, result.answer, 'chat-ai');
            issueChatHistory.push({ user: query, ai: result.answer });
        } catch (error) {
            appendChatMessage(issueChatContainer, `❌ Error: ${error.message}`, 'chat-ai');
        } finally {
            setLoadingState(btn, false, 'Send');
            issueChatContainer.scrollTop = issueChatContainer.scrollHeight;
        }
    }

    async function handleQuery() {
        const query = document.getElementById('query-input').value.trim();
        if (!query) return;
        
        const btn = document.getElementById('query-btn');
        const chatContainer = document.getElementById('chat-container');
        
        appendChatMessage(chatContainer, query, 'chat-user');
        document.getElementById('query-input').value = '';
        
        setChatButtonStatus(btn, 'Starting analysis...');
        
        try {
            // Step 1: Initial analysis and planning
            setChatButtonStatus(btn, 'Analyzing query...');
            const response = await fetch('/api/chat/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    query: query, 
                    history: chatHistory.slice(-3) // Last 3 exchanges
                })
            });
            
            if (!response.ok) {
                throw new Error(`Analysis failed: ${response.status}`);
            }
            
            const analysisResult = await response.json();
            
            // Step 2: Execute the planned searches and get final response
            setChatButtonStatus(btn, 'Searching logs...');
            const finalResponse = await fetch('/api/chat/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    query: query,
                    analysis: analysisResult,
                    history: chatHistory.slice(-3)
                })
            });
            
            if (!finalResponse.ok) {
                throw new Error(`Execution failed: ${finalResponse.status}`);
            }
            
            const result = await finalResponse.json();
            appendChatMessage(chatContainer, result.answer, 'chat-ai');
            chatHistory.push({ user: query, ai: result.answer });
            
        } catch (error) {
            console.error('Chat error:', error);
            appendChatMessage(chatContainer, `❌ Error: ${error.message}`, 'chat-ai');
        } finally {
            setChatButtonStatus(btn, 'idle');
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
    }

    function clearChat() {
        const chatContainer = document.getElementById('chat-container');
        chatHistory = [];
        chatContainer.innerHTML = `
            <div class="chat-bubble chat-ai">
                👋 Hello! I'm your AI security analyst. Ask me anything about your logs, threats, or security issues.
            </div>
        `;
    }

    function appendChatMessage(container, message, className) {
        const bubble = document.createElement('div');
        bubble.className = `chat-bubble ${className} text-white whitespace-pre-wrap`;
        
        if (className === 'chat-ai') {
            bubble.innerHTML = renderMarkdown(message);
        } else {
            bubble.textContent = message;
        }
        
        container.appendChild(bubble);
        container.scrollTop = container.scrollHeight;
    }

    function setChatButtonStatus(button, status) {
        const spinner = button.querySelector('.loading-spinner');
        const text = button.querySelector('.query-btn-text');
        
        if (status === 'idle') {
            button.disabled = false;
            if (spinner) spinner.classList.add('hidden');
            text.textContent = 'Send';
        } else {
            button.disabled = true;
            if (spinner) spinner.classList.remove('hidden');
            text.textContent = status;
        }
    }

    async function generateScript(issueId, issueTitle) {
        document.getElementById('script-issue-title').textContent = issueTitle;
        document.getElementById('script-content').innerHTML = `
            <div class="flex items-center gap-2 text-blue-400">
                <div class="loading-spinner"></div>
                Generating comprehensive diagnosis and repair script...
            </div>
        `;
        document.getElementById('script-modal').style.display = 'flex';
        
        try {
            const response = await fetch(`/api/issues/${issueId}/generate-script`, { method: 'POST' });
            if (!response.ok) throw new Error('Failed to generate script');
            const result = await response.json();
            document.getElementById('script-content').textContent = result.script;
            showToast('Script generated successfully!');
        } catch (error) {
            document.getElementById('script-content').textContent = `❌ Error generating script: ${error.message}`;
            showToast('Failed to generate script', 'error');
        }
    }

    function openFullIssuesModal(issues, modalTitle = "All Issues") {
        const modal = document.getElementById('full-issues-modal');
        const container = document.getElementById('full-issues-container');
        const titleElement = document.getElementById('full-issues-modal-title');
        
        // Store for filtering - use a separate variable to avoid overwriting global allIssues
        window.currentModalIssues = issues || [];
        titleElement.textContent = modalTitle;
        
        // Reset filters when opening modal
        document.getElementById('modal-severity-filter').value = '';
        document.getElementById('modal-sort-issues').value = 'timestamp-desc';
        document.getElementById('modal-search-issues').value = '';
        
        displayModalIssues(issues);
        modal.style.display = 'flex';
    }

    function displayModalIssues(issues) {
        const container = document.getElementById('full-issues-container');
        
        if (!container) {
            console.error('Full issues container not found');
            return;
        }
        
        console.log('displayModalIssues called with', issues ? issues.length : 0, 'issues');
        container.innerHTML = '';
        
        if (!issues || issues.length === 0) {
            container.innerHTML = `
                <div class="col-span-full text-center py-12">
                    <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                        <span class="text-2xl">OK</span>
                    </div>
                    <p class="text-gray-400 text-lg">No security issues match your filters</p>
                    <p class="text-gray-500 text-sm mt-2">Try adjusting your search criteria</p>
                </div>
            `;
            return;
        }
        
        // Update grid/list classes
        if (isGridView) {
            container.className = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[70vh] overflow-y-auto custom-scrollbar';
        } else {
            container.className = 'space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar';
        }
        
        // Limit issues to prevent performance issues
        const issuesToDisplay = issues; // Show all issues in modal
        
        console.log(`Displaying ${issuesToDisplay.length} issues in modal`);
        
        issuesToDisplay.forEach((issue, index) => {
            try {
                const issueEl = document.createElement('div');
                issueEl.className = `glass-card p-4 severity-${issue.severity} ${isGridView ? 'h-fit' : ''}`;
                
                const severityIcons = {
                    'Critical': 'CRIT',
                    'High': 'HIGH',
                    'Medium': 'MED',
                    'Low': 'LOW'
                };
                
                const severityColors = {
                    'Critical': 'text-red-400 bg-red-500/20',
                    'High': 'text-orange-400 bg-orange-500/20',
                    'Medium': 'text-yellow-400 bg-yellow-500/20',
                    'Low': 'text-green-400 bg-green-500/20'
                };

                const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                    ? issue.related_logs.slice(0, 3).map((logId, idx) => {
                        // Handle both string IDs and objects
                        const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                        return `<button class="log-button text-xs" data-log-id="${actualLogId}" title="Click to view log details">
                            ${actualLogId.substring(0, 6)}...
                        </button>`;
                      }).join('')
                    : '<span class="text-gray-500 text-xs">No logs</span>';

                issueEl.innerHTML = `
                    <div class="flex justify-between items-start mb-3">
                        <div class="flex items-center gap-2">
                            <div class="w-6 h-6 rounded ${severityColors[issue.severity]} flex items-center justify-center text-sm">
                                ${severityIcons[issue.severity]}
                            </div>
                            <div>
                                <span class="text-xs font-bold uppercase ${severityColors[issue.severity].split(' ')[0]} block">
                                    ${issue.severity}
                                </span>
                                <h3 class="font-bold text-sm text-white leading-tight">${escapeHtml(issue.title || 'Untitled Issue')}</h3>
                            </div>
                        </div>
                        <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                            ${new Date(issue.timestamp).toLocaleTimeString()}
                        </span>
                    </div>
                    
                    <div class="text-gray-300 mb-3 text-sm leading-relaxed ${isGridView ? 'line-clamp-3' : ''}">${renderMarkdown(issue.summary || 'No summary available')}</div>
                    
                    <details class="mb-3">
                        <summary class="cursor-pointer text-blue-400 hover:text-blue-300 text-sm mb-2" onclick="event.stopPropagation();">
                            📋 Details & Logs
                        </summary>
                        <div class="mt-2 p-3 bg-black/20 rounded border border-gray-700/50" onclick="event.stopPropagation();">
                            <div class="mb-3">
                                <h4 class="font-semibold text-white text-sm mb-1"> Actions:</h4>
                                <div class="text-gray-300 text-sm">${renderMarkdown((issue.recommendation || 'No recommendations available').substring(0, 200))}${(issue.recommendation && issue.recommendation.length > 200) ? '...' : ''}</div>
                            </div>
                            <div>
                                <h4 class="font-semibold text-white text-sm mb-1">📄 Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                                <div class="flex flex-wrap gap-1">
                                    ${relatedLogsHtml}
                                </div>
                            </div>
                        </div>
                    </details>
                    
                    <div class="flex gap-1 flex-wrap">
                        <button class="action-btn ignore-btn text-xs py-1 px-2" data-issue-id="${issue.id}">
                            🗑️ Ignore
                        </button>
                        <button class="action-btn chat-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${escapeHtml(issue.title || '')}">
                            💬 Chat
                        </button>
                        <button class="action-btn script-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${escapeHtml(issue.title || '')}">
                            🔧 Script
                        </button>
                    </div>
                `;
                container.appendChild(issueEl);
            } catch (error) {
                console.error(`Error rendering issue ${index}:`, error, issue);
            }
        });
        
        console.log(`Successfully displayed ${issuesToDisplay.length} issues in modal`);
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function applyModalFilters() {
        const severityFilter = document.getElementById('modal-severity-filter').value;
        const sortBy = document.getElementById('modal-sort-issues').value;
        const searchTerm = document.getElementById('modal-search-issues').value.toLowerCase();
        
        // Use currentModalIssues instead of allIssues to preserve category filtering
        let filteredIssues = [...(window.currentModalIssues || allIssues)];
        
        // Apply severity filter
        if (severityFilter) {
            filteredIssues = filteredIssues.filter(issue => issue.severity === severityFilter);
        }
        
        // Apply search filter
        if (searchTerm) {
            filteredIssues = filteredIssues.filter(issue => 
                issue.title.toLowerCase().includes(searchTerm) ||
                issue.summary.toLowerCase().includes(searchTerm)
            );
        }
        
        // Apply sorting
        filteredIssues.sort((a, b) => {
            switch(sortBy) {
                case 'timestamp-desc':
                    return new Date(b.timestamp) - new Date(a.timestamp);
                case 'timestamp-asc':
                    return new Date(a.timestamp) - new Date(b.timestamp);
                case 'severity-desc':
                    const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                    return severityOrder[b.severity] - severityOrder[a.severity];
                case 'severity-asc':
                    const severityOrderAsc = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                    return severityOrderAsc[a.severity] - severityOrderAsc[b.severity];
                case 'title-asc':
                    return a.title.localeCompare(b.title);
                default:
                    return 0;
            }
        });
        
        displayModalIssues(filteredIssues);
    }

    // Modal Functions
    const logModal = document.getElementById('log-modal');
    const issueQueryModal = document.getElementById('issue-query-modal');
    const settingsModal = document.getElementById('settings-modal');
    const scriptModal = document.getElementById('script-modal');
    const fullIssuesModal = document.getElementById('full-issues-modal');
    const ruleAnalysisModal = document.getElementById('rule-analysis-modal');

    async function showLogModal(logId) {
        const logContent = document.getElementById('log-content');
        logContent.innerHTML = '<div class="loading-spinner"></div> Loading log details...';
        logModal.style.display = 'flex';
        
        try {
            const res = await fetch(`/api/logs/${logId}`);
            if (!res.ok) throw new Error(`Failed to fetch log ${logId}`);
            const data = await res.json();
            logContent.textContent = JSON.stringify(data, null, 2);
        } catch (e) {
            logContent.textContent = `❌ Error: ${e.message}`;
        }
    }

    // Event Listeners
    document.addEventListener('click', (event) => {
        // Log buttons
        if (event.target.matches('.log-button')) {
            showLogModal(event.target.dataset.logId);
        }
        
        // Issue action buttons
        if (event.target.matches('.ignore-btn')) {
            if (confirm('Are you sure you want to ignore this security issue?')) {
                ignoreIssue(event.target.dataset.issueId);
            }
        }
        
        if (event.target.matches('.chat-btn')) {
            openIssueQueryModal(event.target.dataset.issueId, event.target.dataset.issueTitle);
        }
        
        if (event.target.matches('.script-btn')) {
            generateScript(event.target.dataset.issueId, event.target.dataset.issueTitle);
        }
    });

    // Modal close handlers
    document.getElementById('close-log-modal-btn').onclick = () => logModal.style.display = 'none';
    document.getElementById('close-issue-query-modal-btn').onclick = () => issueQueryModal.style.display = 'none';
    document.getElementById('close-script-modal-btn').onclick = () => scriptModal.style.display = 'none';
    document.getElementById('close-settings-modal-btn').onclick = () => settingsModal.style.display = 'none';
    document.getElementById('close-full-issues-modal-btn').onclick = () => fullIssuesModal.style.display = 'none';
    document.getElementById('close-rule-analysis-modal-btn').onclick = () => {
        ruleAnalysisModal.style.display = 'none';
        selectedRuleFilter = null;
    };

    // Click outside to close modals
    window.onclick = (event) => {
        if (event.target == logModal) logModal.style.display = 'none';
        if (event.target == issueQueryModal) issueQueryModal.style.display = 'none';
        if (event.target == settingsModal) settingsModal.style.display = 'none';
        if (event.target == scriptModal) scriptModal.style.display = 'none';
        if (event.target == fullIssuesModal) fullIssuesModal.style.display = 'none';
        if (event.target == ruleAnalysisModal) {
            ruleAnalysisModal.style.display = 'none';
            selectedRuleFilter = null;
        }
    };

    // Rule chart click handler
    document.getElementById('rule-chart-card').addEventListener('click', () => {
        openRuleAnalysisModal();
    });

    // Security issues header click handler
    document.getElementById('security-issues-header').addEventListener('click', async () => {
        console.log('Security issues header clicked');
        await showIssuesModal('security');
    });
    
    document.getElementById('operational-issues-header').addEventListener('click', async () => {
        console.log('Operational issues header clicked');
        await showIssuesModal('operational');
    });
    
    async function showIssuesModal(category) {
        try {
            // Use existing issues data if available, otherwise fetch fresh data
            let issuesToShow = allIssues;
            
            if (!issuesToShow || issuesToShow.length === 0) {
                console.log('No cached issues, fetching fresh data...');
                const response = await fetch('/api/dashboard');
                if (response.ok) {
                    const data = await response.json();
                    issuesToShow = data.issues || [];
                    allIssues = issuesToShow; // Cache for future use
                } else {
                    throw new Error('Failed to fetch dashboard data');
                }
            }
            
            // Filter issues by category
            const filteredIssues = issuesToShow.filter(issue => issue.category === category);
            const categoryLabel = category === 'security' ? 'Security' : 'Operational';
            
            console.log(`Opening ${categoryLabel} issues modal with`, filteredIssues.length, 'issues');
            openFullIssuesModal(filteredIssues, `${categoryLabel} Issues`);
            
        } catch (error) {
            console.error('Failed to open full issues view:', error);
            showToast('Failed to load issues view. Please try again.', 'error');
        }
    }

    // Chat input handlers
    document.getElementById('query-btn').addEventListener('click', handleQuery);
    document.getElementById('query-input').addEventListener('keyup', (event) => {
        if (event.key === 'Enter') handleQuery();
    });
    document.getElementById('clear-chat-btn').addEventListener('click', clearChat);

    // Modal filtering handlers
    document.getElementById('modal-severity-filter').addEventListener('change', applyModalFilters);
    document.getElementById('modal-sort-issues').addEventListener('change', applyModalFilters);
    document.getElementById('modal-search-issues').addEventListener('input', applyModalFilters);
    document.getElementById('modal-clear-filters').addEventListener('click', () => {
        document.getElementById('modal-severity-filter').value = '';
        document.getElementById('modal-sort-issues').value = 'timestamp-desc';
        document.getElementById('modal-search-issues').value = '';
        applyModalFilters();
    });

    // Rule modal filtering handlers
    document.getElementById('rule-severity-filter').addEventListener('change', filterRuleIssues);
    document.getElementById('rule-search-issues').addEventListener('input', filterRuleIssues);
    document.getElementById('rule-clear-filters').addEventListener('click', () => {
        document.getElementById('rule-severity-filter').value = '';
        document.getElementById('rule-search-issues').value = '';
        selectedRuleFilter = null;
        filterRuleIssues();
    });

    // Grid/List view handlers
    document.getElementById('grid-view-btn').addEventListener('click', () => {
        isGridView = true;
        document.getElementById('grid-view-btn').classList.add('bg-blue-600');
        document.getElementById('grid-view-btn').classList.remove('bg-gray-600');
        document.getElementById('list-view-btn').classList.add('bg-gray-600');
        document.getElementById('list-view-btn').classList.remove('bg-blue-600');
        applyModalFilters();
    });

    document.getElementById('list-view-btn').addEventListener('click', () => {
        isGridView = false;
        document.getElementById('list-view-btn').classList.add('bg-blue-600');
        document.getElementById('list-view-btn').classList.remove('bg-gray-600');
        document.getElementById('grid-view-btn').classList.add('bg-gray-600');
        document.getElementById('grid-view-btn').classList.remove('bg-blue-600');
        applyModalFilters();
    });

    document.getElementById('issue-query-btn').addEventListener('click', handleIssueQuery);
    document.getElementById('issue-query-input').addEventListener('keyup', (event) => {
        if (event.key === 'Enter') handleIssueQuery();
    });

    // Main action buttons
    document.getElementById('find-more-btn').addEventListener('click', triggerAnalysis);
    document.getElementById('settings-btn').addEventListener('click', () => {
        loadSettings();
        settingsModal.style.display = 'flex';
    });

    // Script actions
    document.getElementById('copy-script-btn').onclick = () => {
        const scriptText = document.getElementById('script-content').textContent;
        navigator.clipboard.writeText(scriptText).then(() => {
            showToast('Script copied to clipboard!');
        });
    };

    document.getElementById('download-script-btn').onclick = () => {
        const scriptText = document.getElementById('script-content').textContent;
        const blob = new Blob([scriptText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wazuh_repair_script_${new Date().getTime()}.sh`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Script downloaded successfully!');
    };

    // Help modal functionality
    function showHelpModal() {
        const modal = document.getElementById('help-modal');
        modal.style.display = 'flex';
    }
    
    document.getElementById('help-btn').onclick = showHelpModal;
    document.getElementById('close-help-modal-btn').onclick = () => {
        document.getElementById('help-modal').style.display = 'none';
    };

    // Settings handling
    document.getElementById('settings-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const formData = Object.fromEntries(new FormData(event.target));
        saveSettings(formData);
    });

    document.getElementById('clear-db-btn').addEventListener('click', () => {
        if (confirm('WARNING: Are you sure you want to clear the entire database? This action cannot be undone and will remove all logs, issues, and analysis data.')) {
            clearDatabase();
        }
    });

    async function loadSettings() {
        try {
            const response = await fetch('/api/settings');
            if (!response.ok) throw new Error('Failed to load settings');
            const settings = await response.json();
            const form = document.getElementById('settings-form');
            for (const [key, value] of Object.entries(settings)) {
                const input = form.querySelector(`[name="${key}"]`);
                if (input) input.value = value;
            }
        } catch (error) {
            console.error("Failed to load settings:", error);
            showToast('Failed to load settings', 'error');
        }
    }

    async function saveSettings(formData) {
        try {
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });
            if (!response.ok) throw new Error('Failed to save settings');
            settingsModal.style.display = 'none';
            showToast('Settings saved successfully!');
        } catch (error) {
            console.error("Failed to save settings:", error);
            showToast('Failed to save settings', 'error');
        }
    }

    async function clearDatabase() {
        try {
            const response = await fetch('/api/clear_db', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to clear database');
            fetchData();
            settingsModal.style.display = 'none';
            showToast('Database cleared successfully!');
        } catch (error) {
            console.error("Failed to clear database:", error);
            showToast('Failed to clear database', 'error');
        }
    }

    // Power user keyboard shortcuts
    document.addEventListener('keydown', (event) => {
        // Check if user is typing in an input field
        if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
            return;
        }
        
        if (event.ctrlKey) {
            switch(event.key) {
                case 'f':
                case 'F':
                    event.preventDefault();
                    document.getElementById('find-more-btn').click();
                    break;
                case 'r':
                case 'R':
                    event.preventDefault();
                    fetchData();
                    showToast('Data refreshed', 'success');
                    break;
                case 's':
                case 'S':
                    event.preventDefault();
                    document.getElementById('settings-btn').click();
                    break;
                case 'c':
                case 'C':
                    event.preventDefault();
                    document.getElementById('query-input').focus();
                    break;
                case 'h':
                case 'H':
                    event.preventDefault();
                    showHelpModal();
                    break;
            }
        }
        
        if (event.key === 'Escape') {
            // Close any open modals
            document.querySelectorAll('.modal-backdrop').forEach(modal => {
                modal.style.display = 'none';
            });
        }
    });

    // Initialize everything
    document.addEventListener('DOMContentLoaded', () => {
        console.log('DOM loaded, initializing dashboard...');
        
        try {
            initializeCharts();
            console.log('Charts initialized successfully');
        } catch (error) {
            console.error('Error initializing charts:', error);
        }
        
        try {
            fetchData();
            console.log('Initial data fetch started');
        } catch (error) {
            console.error('Error during initial data fetch:', error);
        }
        
        // Regular refresh every 15 seconds
        setInterval(() => {
            try {
                fetchData();
            } catch (error) {
                console.error('Error during periodic data fetch:', error);
            }
        }, 15000);
        
        // More frequent status updates every 3 seconds when app is active
        setInterval(() => {
            try {
                const currentStatus = document.getElementById('app-status')?.textContent;
                if (currentStatus && !currentStatus.includes('Idle') && !currentStatus.includes('Ready')) {
                    // Fetch data more frequently during active operations
                    fetchData();
                }
            } catch (error) {
                console.error('Error during status check:', error);
            }
        }, 3000);
        
        console.log('Dashboard initialization complete');
    });
</script>

</body>
</html>
"""