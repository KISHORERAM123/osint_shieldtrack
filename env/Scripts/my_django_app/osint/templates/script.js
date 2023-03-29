function generateReport() {
  // Get the URL from the input field
  var url = document.getElementById("url-input").value;

  // Send an HTTP POST request to the server
  fetch("/osint/", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "X-CSRFToken": getCookie("csrftoken"),
    },
    body: "url=" + encodeURIComponent(url),
  })
    .then((response) => response.json())
    .then((data) => {
      // Clear the previous results
      var tableBody = document.getElementById("results-table-body");
      tableBody.innerHTML = "";

      // VirusTotal Report
      if (data.vt_report) {
        var row = tableBody.insertRow();
        var cell1 = row.insertCell();
        var cell2 = row.insertCell();
        cell1.innerHTML = "VirusTotal Report";
        cell2.innerHTML = data.vt_report.positives + " / " + data.vt_report.total;
      }

      // DNS Report
      if (data.dns_report) {
        var row = tableBody.insertRow();
        var cell1 = row.insertCell();
        var cell2 = row.insertCell();
        cell1.innerHTML = "DNS Report";
        cell2.innerHTML = data.dns_report.join(", ");
      }

      // Geolocation Report
      if (data.geopy_report) {
        var row = tableBody.insertRow();
        var cell1 = row.insertCell();
        var cell2 = row.insertCell();
        cell1.innerHTML = "Geolocation Report";
        cell2.innerHTML = data.geopy_report.address;
      }

      // WHOIS Report
      if (data.whois_report) {
        var row = tableBody.insertRow();
        var cell1 = row.insertCell();
        var cell2 = row.insertCell();
        cell1.innerHTML = "WHOIS Report";
        cell2.innerHTML = data.whois_report.registrant_name;
      }

      // UUID Analysis
      if (data.uuid_analysis) {
        var row = tableBody.insertRow();
        var cell1 = row.insertCell();
        var cell2 = row.insertCell();
        cell1.innerHTML = "UUID Analysis";
        cell2.innerHTML = data.uuid_analysis.hex;
      }
    })
    .catch((error) => console.error(error));
}
