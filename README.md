# CVE Coffee Delivery

This Go program identifies critical Common Vulnerabilities and Exposures (CVEs) in the last 24 hrs and automatically orders coffee for the company most likely affected by the vulnerability, using the Terminal.shop API.

## Prerequisites

- Go 1.20 or higher
- A Terminal.shop account and API key
- An OpenAI API key
- A `.env` file containing the necessary environment variables

## Setup

1.  Clone the repository:

```bash
git clone git@github.com:braden-godley/coffee-vulnerabilities.git
cd coffee-vulnerabilities
```

2.  Install dependencies:

```bash
go mod download
```

3.  Create a `.env` file in the root directory with the following content:

```
OPENAI_API_KEY=<your_openai_api_key>
TERMINAL_BEARER_TOKEN=<your_terminal_api_key>
```

Replace `<your_openai_api_key>` and `<your_terminal_api_key>` with your actual API keys.

## Usage

Run the program:

```bash
go run main.go
```

The program will:

1. Fetch recent CVEs from the National Vulnerability Database (NVD).
2. Filter CVEs by severity, only considering 9.0+ scores.
3. For each critical CVE:
    - Use ChatGPT to intelligently determine which company is most likely affected by the CVE, as well as retrieve their address.
    - Use the terminal.shop API to:
        - Create an address for the company.
        - Select a random product that is not decaf and does not require a subscription.
        - Create a card or reuse an existing one.
        - Create an order to send the selected product to the company.

