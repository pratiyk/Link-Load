"""
Simple ZAP Mock Server for Testing
This provides a minimal ZAP API compatible server when ZAP is not available.
For production, use real OWASP ZAP.
"""
from flask import Flask, jsonify, request
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/JSON/core/view/version/', methods=['GET'])
def get_version():
    """Return ZAP version"""
    return jsonify({'version': 'Mock-ZAP-1.0.0'})

@app.route('/JSON/context/action/newContext/', methods=['GET'])
def new_context():
    """Create new context"""
    context_id = request.args.get('contextName', 'default')
    return jsonify({'contextId': hash(context_id) % 10000})

@app.route('/JSON/context/action/includeInContext/', methods=['GET'])
def include_in_context():
    """Include URL in context"""
    return jsonify({'Result': 'OK'})

@app.route('/JSON/spider/action/scan/', methods=['GET'])
def spider_scan():
    """Start spider scan"""
    return jsonify({'scan': '1'})

@app.route('/JSON/ajaxSpider/action/scan/', methods=['GET'])
def ajax_spider_scan():
    """Start AJAX spider scan"""
    return jsonify({'Result': 'OK'})

@app.route('/JSON/ascan/action/scan/', methods=['GET'])
def active_scan():
    """Start active scan"""
    return jsonify({'scan': '1'})

@app.route('/JSON/spider/view/status/', methods=['GET'])
def spider_status():
    """Get spider status"""
    return jsonify({'status': '100'})

@app.route('/JSON/ascan/view/status/', methods=['GET'])
def ascan_status():
    """Get active scan status"""
    return jsonify({'status': '100'})

@app.route('/JSON/core/view/alerts/', methods=['GET'])
def get_alerts():
    """Get alerts (mock vulnerabilities)"""
    return jsonify({
        'alerts': [
            {
                'name': 'Cross Site Scripting (Reflected)',
                'risk': 'High',
                'confidence': 'Medium',
                'url': request.args.get('baseurl', 'http://example.com'),
                'param': 'id',
                'evidence': '<script>alert(1)</script>',
                'solution': 'Validate all input and encode output',
                'reference': 'https://owasp.org/www-community/attacks/xss/',
                'cweid': '79',
                'wascid': '8'
            }
        ]
    })

@app.route('/JSON/spider/view/results/', methods=['GET'])
def spider_results():
    """Get spider results"""
    return jsonify({'results': ['http://example.com', 'http://example.com/page1']})

@app.route('/JSON/core/view/statistics/', methods=['GET'])
def get_stats():
    """Get statistics"""
    return jsonify({'statistics': {}})

@app.route('/JSON/spider/action/stop/', methods=['GET'])
def stop_spider():
    """Stop spider"""
    return jsonify({'Result': 'OK'})

@app.route('/JSON/ascan/action/stop/', methods=['GET'])
def stop_ascan():
    """Stop active scan"""
    return jsonify({'Result': 'OK'})

@app.route('/JSON/context/action/removeContext/', methods=['GET'])
def remove_context():
    """Remove context"""
    return jsonify({'Result': 'OK'})

@app.route('/JSON/alert/action/deleteAllAlerts/', methods=['GET'])
def delete_alerts():
    """Delete all alerts"""
    return jsonify({'Result': 'OK'})

if __name__ == '__main__':
    print("=" * 60)
    print(" Mock ZAP Server Starting")
    print("=" * 60)
    print("\nThis is a lightweight mock of OWASP ZAP for testing.")
    print("For production scanning, use real OWASP ZAP.")
    print("\nServer running on: http://localhost:8090")
    print("API Key: Not required for mock server")
    print("\nTo stop: Press Ctrl+C")
    print("=" * 60)
    app.run(host='0.0.0.0', port=8090, debug=False)
