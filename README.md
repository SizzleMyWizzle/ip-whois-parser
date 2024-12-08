# IP Whois Lookup and Parser

## Description
This Python script performs bulk WHOIS lookups for IP addresses from a .txt file, supporting multithreaded execution and optimized for speed while not requiring any database downloads. It is designed for efficient querying of IP addresses with detailed outputs and several customization options.

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

### Examples
```bash
python3 ip_whois_parser.py input.txt -o output.csv -f csv -v 
```
```bash
python3 ip_whois_parser.py input.txt -v  
```

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
    "network_name": "GOOGLE, US",
    "link": "https://www.whois.com/whois/8.8.8.8",
    "registration_date": "2023-12-28T17:24:33-05:00"
  }
]
```

### CSV Output
| ip_address | country_name   | network_name     | link                                      | registration_date               |
|------------|----------------|------------------|-------------------------------------------|---------------------------------|
| 8.8.8.8    | United States  | GOOGLE, US       | https://www.whois.com/whois/8.8.8.8       | 2023-12-28T17:24:33-05:00       |


### TXT Output
```
IP Address: 8.8.8.8
Country: United States
Network Name: GOOGLE, US
Link: https://www.whois.com/whois/8.8.8.8
Registration Date: 2023-12-28T17:24:33-05:00
===============================
```
---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## Contributions
Contributions are welcome! Feel free to fork the repository, make changes, and submit a pull request.

---

## Support
If you encounter issues or have questions, open an issue in the repository or contact the maintainer.

