# IP Whois Lookup and Parser

## Description
This Python script performs bulk WHOIS lookups for IP addresses, supporting multithreaded execution and caching of network blocks. It is designed for efficient querying of IP addresses with detailed outputs and several customization options.

---

## Features
- **Multithreaded Execution**: Fast processing of large lists of IP addresses.
- **Network Block Caching**: Avoids redundant lookups by caching results for IP within the same advertised subnet.
- **Output Formats**: Supports JSON, CSV, and plain text output.
- **Special-Use IP Filtering**: Automatically skips private and special-use IP ranges.
- **Debug Mode**: Logs additional details such as warnings for country code discrepancies.
- **Error Handling**: Retries failed WHOIS lookups and gracefully handles invalid IPs.

---

## Requirements
- **Python 3.7 or higher**
- Python modules (only external ones require installation):
  - ipwhois
  - pycountry
  - tqdm

Install dependencies with:
```bash
pip install ipwhois pycountry tqdm

```

---

## Usage
### Command-line Arguments
| Argument           | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `input_file`       | Path to a `.txt` file containing IP addresses (one per line).               |
| `-o, --output`     | Path to save the output file (default: `whois_results.<format>`).           |
| `-f, --format`     | Output format: `txt`, `json`, or `csv` (default: `txt`).                   |
| `-v, --verbose`    | Includes additional WHOIS details in the output.                           |
| `--raw`            | Outputs raw WHOIS data without parsing.                                    |
| `--debug`          | Enables debug mode for detailed logging, such as retry warnings.           |

### Example
```bash
python3 bulk_whois_lookup.py input.txt -o output.json -f json -v 
```

This command will:
1. Read IPs from `input.txt`.
2. Perform WHOIS lookups for each valid IP.
3. Save the results in `output.json` in JSON format with verbose details.
4. Enable debug logs.

---

## Special-Use IP Filtering
The script automatically skips IPs as outlined in RFC 1918 (Private IPs) and RFC 6890 (Special-Purpose IPs)

---

## Output Example (Non verbose)
### JSON Output
```json
[
  {
    "ip_address": "8.8.8.8",
    "country_name": "United States",
    "network_name": "GOOGLE",
    "link": "https://www.whois.com/whois/8.8.8.8",
    "registration_date": "1992-12-01"
  }
]
```

### CSV Output
| IP Address | Country Name   | Network Name | Link                                      | Registration Date |
|------------|----------------|--------------|-------------------------------------------|-------------------|
| 8.8.8.8    | United States  | GOOGLE       | https://www.whois.com/whois/8.8.8.8       | 1992-12-01        |

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## Contributions
Contributions are welcome! Feel free to fork the repository, make changes, and submit a pull request.

---

## Support
If you encounter issues or have questions, open an issue in the repository or contact the maintainer.

