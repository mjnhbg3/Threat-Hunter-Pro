#!/bin/bash

# Setup script for Gemini Embeddings in Threat Hunter Pro
# This script configures the environment for optimal Gemini embedding usage

echo "🚀 Setting up Gemini Embeddings for Threat Hunter Pro"
echo "=================================================="

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "⚠️  This script is designed for Linux environments"
    echo "   For other systems, set environment variables manually"
fi

# Function to validate API key format
validate_api_key() {
    local key=$1
    if [[ ${#key} -lt 10 ]]; then
        return 1
    fi
    return 0
}

# Set up environment variables
echo "🔑 Configuring API Keys..."

# Primary API key (required)
if [[ -z "$GEMINI_API_KEY" ]]; then
    read -p "Enter your primary Gemini API key: " GEMINI_API_KEY
    if ! validate_api_key "$GEMINI_API_KEY"; then
        echo "❌ Invalid API key format"
        exit 1
    fi
    echo "export GEMINI_API_KEY='$GEMINI_API_KEY'" >> ~/.bashrc
    echo "✅ Primary API key configured"
else
    echo "✅ Primary API key already configured"
fi

# Optional secondary keys for redundancy
echo ""
echo "💡 For better rate limit handling, you can configure additional API keys:"
read -p "Enter secondary Gemini API key (optional, press Enter to skip): " GEMINI_API_KEY_2
if [[ -n "$GEMINI_API_KEY_2" ]] && validate_api_key "$GEMINI_API_KEY_2"; then
    echo "export GEMINI_API_KEY_2='$GEMINI_API_KEY_2'" >> ~/.bashrc
    echo "✅ Secondary API key configured"
fi

read -p "Enter tertiary Gemini API key (optional, press Enter to skip): " GEMINI_API_KEY_3
if [[ -n "$GEMINI_API_KEY_3" ]] && validate_api_key "$GEMINI_API_KEY_3"; then
    echo "export GEMINI_API_KEY_3='$GEMINI_API_KEY_3'" >> ~/.bashrc
    echo "✅ Tertiary API key configured"
fi

# Configure embedding provider
echo ""
echo "🧠 Configuring Embedding Provider..."
echo "export EMBEDDING_PROVIDER='gemini'" >> ~/.bashrc
echo "✅ Gemini set as default embedding provider with automatic fallback"

# Configure authentication
echo ""
echo "🔐 Configuring Authentication..."
if [[ -z "$BASIC_AUTH_USER" ]]; then
    read -p "Enter dashboard username: " BASIC_AUTH_USER
    echo "export BASIC_AUTH_USER='$BASIC_AUTH_USER'" >> ~/.bashrc
fi

if [[ -z "$BASIC_AUTH_PASS" ]]; then
    read -s -p "Enter dashboard password: " BASIC_AUTH_PASS
    echo ""
    echo "export BASIC_AUTH_PASS='$BASIC_AUTH_PASS'" >> ~/.bashrc
fi
echo "✅ Authentication configured"

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
if command -v pip &> /dev/null; then
    pip install -r requirements.txt
    echo "✅ Dependencies installed"
else
    echo "⚠️  pip not found. Please install requirements manually:"
    echo "   pip install -r requirements.txt"
fi

# Download spaCy model for NER
echo ""
echo "🧠 Installing NER model..."
if command -v python &> /dev/null; then
    python -m spacy download en_core_web_sm
    echo "✅ spaCy NER model installed"
else
    echo "⚠️  Python not found. Please install spaCy model manually:"
    echo "   python -m spacy download en_core_web_sm"
fi

# Create systemd service file (optional)
echo ""
read -p "Create systemd service for auto-start? (y/N): " create_service
if [[ "$create_service" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/threat-hunter.service"
    SCRIPT_DIR=$(pwd)
    
    sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=Threat Hunter Pro with Gemini Embeddings
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$SCRIPT_DIR
Environment="PATH=$PATH"
EnvironmentFile=/home/$(whoami)/.bashrc
ExecStart=/usr/bin/python run_app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable threat-hunter
    echo "✅ Systemd service created and enabled"
    echo "   Start with: sudo systemctl start threat-hunter"
    echo "   Check status: sudo systemctl status threat-hunter"
fi

# Test configuration
echo ""
echo "🧪 Testing configuration..."
source ~/.bashrc

# Run the test script
if [[ -f "test_gemini_embeddings.py" ]]; then
    echo "Running embedding test..."
    python test_gemini_embeddings.py
    if [[ $? -eq 0 ]]; then
        echo "✅ Configuration test passed"
    else
        echo "❌ Configuration test failed - check your API keys"
        exit 1
    fi
else
    echo "⚠️  Test script not found, skipping validation"
fi

echo ""
echo "🎉 Gemini Embeddings Setup Complete!"
echo "=================================================="
echo ""
echo "📋 Configuration Summary:"
echo "  • Embedding Provider: Gemini (with SentenceTransformers fallback)"
echo "  • Rate Limits: 100 RPM, 30K TPM, 1,000 RPD per API key"
echo "  • Fallback: Automatic switch to local embeddings when daily limits exceeded"
echo "  • API Keys: $([[ -n "$GEMINI_API_KEY" ]] && echo "1")$([[ -n "$GEMINI_API_KEY_2" ]] && echo "+1")$([[ -n "$GEMINI_API_KEY_3" ]] && echo "+1") configured"
echo ""
echo "🚀 To start Threat Hunter Pro:"
echo "  python run_app.py"
echo ""
echo "🌐 Access dashboard at: http://localhost:8000"
echo "  Username: $BASIC_AUTH_USER"
echo "  Password: [configured]"
echo ""
echo "📊 Monitor usage:"
echo "  • Dashboard shows current embedding provider"
echo "  • Logs indicate API key rotation and fallback events"
echo "  • Metrics endpoint: http://localhost:8000/metrics"
echo ""
echo "⚠️  Important Notes:"
echo "  • Gemini API usage is metered - monitor your quota"
echo "  • Daily limits reset at midnight UTC"
echo "  • Fallback to local embeddings is automatic and seamless"
echo "  • For production, consider multiple API keys for redundancy"
echo ""
echo "📚 Documentation: See GEMINI_EMBEDDINGS_README.md for details"