# Nillion Signature Tools

### Available Tools:

- **ECDSA Key Generator**: Generate new ECDSA key pairs
- **Store Key In Nillion**: Store your ECDSA private key in Nillion
- **Retrieve Key from Nillion**: Retrieve your stored ECDSA private key from Nillion
- **Sign Message**: Sign messages securely using Nillion's threshold ECDSA via your stored private key
- **Verify Signature**: Verify the authenticity of signed messages
- **Other Tools**: Explore additional dev tools that help generate a Nillion user ID from a seed, derive Ethereum addresses, and derive public keys

## Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- run `nillion-devnet`

### Installation

1. Clone the repository:
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On macOS/Linux
   .venv\Scripts\activate     # On Windows
   ```
3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the Streamlit app:

   Make sure `nillion-devnet` is alreaedy running. Then start the local streamlit app with

   ```bash
   streamlit run app.py
   ```
