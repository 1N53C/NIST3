import tkinter as tk
import requests

# Create the main window
window = tk.Tk()
window.title("CVE Search")
window.geometry("1600x1200")  # Set the window size

# Create the text fields for the vendor and product
vendor_label = tk.Label(text="Vendor:")
vendor_field = tk.Entry()
product_label = tk.Label(text="Product:")
product_field = tk.Entry()
version_label = tk.Label(text="Version:")
version_field = tk.Entry()

# Create the search button
def search_cves():
    vendor = vendor_field.get()
    product = product_field.get()
    #version = version_field.get()

    # Send the request to the NVD
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    virtual_match_string = f"cpe:2.3:a:{vendor}:{product}:v:{version}"
    #virtual_match_string = f"cpe:2.3:a:{vendor}:{product}"
    print(virtual_match_string)
    params = {"virtualMatchString": virtual_match_string}
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        cves = response.json()

        result_text.delete("1.0", tk.END)  # Clear the text area
        result = "Number of CVEs: " + str(cves['totalResults']) + "\n\n"
        # Format the output
        for cve in cves['vulnerabilities']:
            result += "CVE ID: " + cve['cve']['id'] + "\n"
            result += "Description: " + cve['cve']['descriptions'][0]['value'] + "\n"
            try:
                cvss_score = None
                if 'cvssMetricV2' in cve['cve']['metrics']:
                    # Extract the first entry from the list
                    cvss_score = cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    result += "CVSS Score: " + str(cvss_score) + "\n"
                if 'cvssMetricV31' in cve['cve']['metrics']:
                    result += "Access Vector: " + cve['cve']['metrics']['cvssMetricV2'][0]['cvssData'][
                        'accessVector'] + "\n"
                    result += "Confidentiality Impact: " + cve['cve']['metrics']['cvssMetricV2'][0]['cvssData'][
                        'confidentialityImpact'] + "\n"
                    result += "Integrity Impact: " + cve['cve']['metrics']['cvssMetricV2'][0]['cvssData'][
                        'integrityImpact'] + "\n"
                    result += "Availability Impact: " + cve['cve']['metrics']['cvssMetricV2'][0]['cvssData'][
                        'availabilityImpact'] + "\n"
                    result += "Base Severity: " + cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
            except KeyError:
                result += "CVSS Score: N/A\n"

            result += "---\n"
        result_text.insert(tk.END, result)  # Insert the new text
    else:
        result_text.delete("1.0", tk.END)  # Clear the text area
        result_text.insert(tk.END, "An error occurred")  # Insert the new text

search_button = tk.Button(text="Search", command=search_cves)

# Create the text area for displaying the output
result_text = tk.Text()

# Add the text fields and button to the window
vendor_label.pack()
vendor_field.pack()
product_label.pack()
product_field.pack()
version_label.pack()
version_field.pack()
search_button.pack()
result_text.config(height=600, width=1600)
result_text.pack()

# Run the main loop
window.mainloop()

