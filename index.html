<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Information</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f0f0f0;
        }
        h1 {
            text-align: center;
            font-size: 24px;
            margin-bottom: 20px;
        }
        #info {
            background-color: white;
            padding: 20px;
            border: 1px solid #ccc;
            max-width: 600px;
            margin: 0 auto;
        }
        #info div {
            margin-bottom: 10px;
        }
        #info strong {
            display: inline-block;
            width: 150px;
        }
    </style>
    <script src="fingerprint2.js"></script>
</head>
<body>
    <h1>Your Network Information</h1>
    <div id="info">
        <div><strong>IPv4:</strong> <span id="ipv4">Loading...</span></div>
        <div><strong>IPv6:</strong> <span id="ipv6">Loading...</span></div>
        <div><strong>City:</strong> <span id="city">Loading...</span></div>
        <div><strong>Country:</strong> <span id="country">Loading...</span></div>
        <div><strong>ISP:</strong> <span id="isp">Loading...</span></div>
        <div><strong>ISP ASN:</strong> <span id="asn">Loading...</span></div>
        <div><strong>WebRTC IP:</strong> <span id="webrtc">Loading...</span></div>
        <div><strong>DNS:</strong> <span id="dns">Loading...</span></div>
        <div><strong>OS:</strong> <span id="os">Loading...</span></div>
        <div><strong>MTU:</strong> <span id="mtu">Loading...</span></div>
        <div><strong>JA4T:</strong> <span id="ja4t">Loading...</span></div>
    </div>

    <script>
        // Replace with your ipgeolocation.io API key
        const IPGEOLOCATION_API_KEY = 'YOUR_IPGEOLOCATION_API_KEY';

        // Fetch IP and geolocation data using ipgeolocation.io with fallback to ipinfo.io
        async function fetchGeoData() {
            try {
                let response = await fetch(`https://api.ipgeolocation.io/ipgeo?apiKey=${IPGEOLOCATION_API_KEY}`);
                if (!response.ok) throw new Error('ipgeolocation.io failed');
                let data = await response.json();
                document.getElementById('ipv4').textContent = data.ip || 'Not available';
                document.getElementById('ipv6').textContent = data.ipv6 || 'Not available';
                document.getElementById('city').textContent = data.city || 'Not available';
                document.getElementById('country').textContent = data.country_name || 'Not available';
                document.getElementById('isp').textContent = data.isp || 'Not available';
                document.getElementById('asn').textContent = data.asn || 'Not available';
            } catch (error) {
                console.error('Error fetching geo data:', error);
                // Fallback to ipinfo.io
                try {
                    let response = await fetch('https://ipinfo.io/json');
                    let data = await response.json();
                    document.getElementById('ipv4').textContent = data.ip || 'Not available';
                    document.getElementById('ipv6').textContent = 'Not available';
                    document.getElementById('city').textContent = data.city || 'Not available';
                    document.getElementById('country').textContent = data.country || 'Not available';
                    document.getElementById('isp').textContent = data.org || 'Not available';
                    document.getElementById('asn').textContent = data.asn || 'Not available';
                } catch (fallbackError) {
                    console.error('Fallback failed:', fallbackError);
                    document.querySelectorAll('#ipv4, #ipv6, #city, #country, #isp, #asn')
                        .forEach(el => el.textContent = 'Error');
                }
            }
        }
        fetchGeoData();

        // Fetch WebRTC IP
        function getWebRTCIP() {
            if (!window.RTCPeerConnection && !window.webkitRTCPeerConnection && !window.mozRTCPeerConnection) {
                document.getElementById('webrtc').textContent = 'Disabled';
                return;
            }
            const servers = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
            const pc = new (window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection)(servers);
            const ips = new Set();
            pc.createDataChannel('');
            pc.onicecandidate = (e) => {
                if (e.candidate && e.candidate.candidate) {
                    const ipMatch = e.candidate.candidate.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
                    if (ipMatch) ips.add(ipMatch[1]);
                }
                if (!e.candidate) {
                    document.getElementById('webrtc').textContent = ips.size > 0 ? Array.from(ips).join(', ') : 'No IPs found';
                    pc.close();
                }
            };
            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(() => document.getElementById('webrtc').textContent = 'Error');
        }
        getWebRTCIP();

        // Fetch DNS information using a public resolver
        async function getDNSInfo() {
            try {
                // Using a WHOIS-based resolver check (simplified)
                let response = await fetch('https://dns.google/resolve?name=whoami.akamai.net&type=A');
                let data = await response.json();
                if (data.Status === 0 && data.Answer) {
                    document.getElementById('dns').textContent = data.Answer[0].data || 'Unknown';
                } else {
                    document.getElementById('dns').textContent = 'Not resolved';
                }
            } catch (error) {
                console.error('Error fetching DNS:', error);
                document.getElementById('dns').textContent = 'Not available';
            }
        }
        getDNSInfo();

        // TCP/IP Fingerprinting with improved configuration
        function initFingerprint() {
            if (typeof Fingerprint2 === 'undefined') {
                console.error('Fingerprint2 not loaded');
                document.getElementById('ja4t').textContent = 'Failed to load library';
                document.getElementById('os').textContent = 'Failed to load library';
                document.getElementById('mtu').textContent = 'Failed to load library';
                return;
            }
            const options = {
                fonts: { extendedJsFonts: true },
                excludes: {
                    enumerateDevices: true,
                    fontsFlash: true,
                    adBlock: true
                }
            };
            Fingerprint2.get(options, components => {
                const values = components.map(c => `${c.key}:${c.value}`);
                const ja4t = Fingerprint2.x64hash128(values.join(';'), 31); // Enhanced JA4T-like fingerprint
                document.getElementById('ja4t').textContent = ja4t;

                // Improved OS detection
                const userAgent = navigator.userAgent;
                const platform = navigator.platform || 'Unknown';
                let os = 'Unknown';
                if (/Win(dows)?/.test(platform) || /Windows/.test(userAgent)) os = 'Windows';
                else if (/Mac/.test(platform) || /Mac OS/.test(userAgent)) os = 'Mac OS';
                else if (/Linux/.test(platform) || /Linux/.test(userAgent)) os = 'Linux';
                else if (/Android/.test(userAgent)) os = 'Android';
                else if (/iPhone|iPad|iPod/.test(userAgent)) os = 'iOS';
                // Refine with version if available
                const osMatch = userAgent.match(/(Windows NT \d+\.\d+)|Mac OS X (\d+_\d+_\d+)|Android (\d+\.\d+)|iOS (\d+\.\d+)/);
                if (osMatch) os += ` ${osMatch[1] || osMatch[2]?.replace('_', '.') || osMatch[3] || osMatch[4] || ''}`;
                document.getElementById('os').textContent = os;

                // MTU (still not measurable in browser, using default)
                document.getElementById('mtu').textContent = '1500 (assumed default)';
            });
        }

        // Run Fingerprint2 after window load
        window.addEventListener('load', initFingerprint);
    </script>
</body>
</html>
