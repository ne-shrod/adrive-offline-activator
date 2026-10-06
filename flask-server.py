from flask import Flask, request, Response
app = Flask(__name__)

cr = (
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
    '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
    '<CheckForUpdateResponse xmlns="http://tempuri.org/">'
    '<CheckForUpdateResult/>'
    '</CheckForUpdateResponse>'
    '</s:Body>'
    '</s:Envelope>'
)

ar = (
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
    '<s:Body>'
    '<ActivateResponse xmlns="http://tempuri.org/">'
    '<ActivateResult xmlns:a="http://schemas.datacontract.org/2004/07/" '
    'xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'
    '<a:Code>552E-6FEF-A149-A244-A7F4-23F0-4D40-E039-54B3-6B51-5224-E04A-6794-C04F-7D03-1071-05AC-CAA3-FD4C-2757</a:Code>'
    '</ActivateResult>'
    '</ActivateResponse>'
    '</s:Body>'
    '</s:Envelope>'
)

sf = (
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
    '<s:Body><s:Fault>'
    '<faultcode>s:Client</faultcode>'
    '<faultstring>Invalid key</faultstring>'
    '</s:Fault></s:Body>'
    '</s:Envelope>'
)

def lr():
    for k, v in request.headers.items():
        print(f"       {k}: {v}")
    body = request.get_data(as_text=True) or ""
    return body

@app.route('/Service.svc', methods=['POST', 'GET'])
def service():
    body = lr()
    sa = request.headers.get('SOAPAction', '')

    if 'Activate' in sa:
        if "2601-2988-6197" in body and "50-02-01-13-62-67-59-86" in body:
            return Response(
                ar,
                status=200,
                headers={
                    'Content-Type': 'text/xml; charset=utf-8',
                    'Server': 'Microsoft-IIS/10.0',
                    'Alt-Svc': 'h3=":443"; ma=86400; persist=1',
                    'Content-Length': str(len(ar.encode('utf-8'))),
                }
            )
        return Response(
            sf,
            status=500,
            headers={'Content-Type': 'text/xml; charset=utf-8',
                     'Server': 'Microsoft-IIS/10.0'}
        )

    return Response(
        cr,
        status=200,
        headers={
            'Content-Type': 'text/xml; charset=utf-8',
            'Server': 'Microsoft-IIS/10.0',
            'Alt-Svc': 'h3=":443"; ma=86400; persist=1',
            'Content-Length': str(len(cr.encode('utf-8'))),
        }
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)