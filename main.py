import time
import ssl
import socket
import whois
import datetime
import dateutil.parser
import dns.resolver
import dns.reversename
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CreateDNS")

# Enable CORS for MVP
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup templates
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def serve_frontend(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/lookup/{domain}")
async def lookup_domain(domain: str, type: str = "A"):
    # Input validation
    valid_record_types = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR"]
    record_type = type.upper()
    
    if record_type not in valid_record_types:
        raise HTTPException(status_code=400, detail=f"Invalid record type. Supported types: {', '.join(valid_record_types)}")
        
    try:
        # Core Engine: dnspython resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        start_time = time.perf_counter()
        
        # Handle reverse PTR
        query_target = domain
        if record_type == "PTR":
            try:
                query_target = dns.reversename.from_address(domain)
            except dns.exception.SyntaxError:
                pass # Not an IP address, pass as string
        
        # Perform the query
        answers = resolver.resolve(query_target, record_type)
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        
        # Prepare structured JSON result
        records = []
        for rdata in answers:
            value = rdata.to_text()
            # Clean up TXT styling if needed
            if record_type == "TXT" and value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
                
            records.append({
                "value": value,
                "ttl": answers.rrset.ttl if hasattr(answers, 'rrset') else None,
                "record_type": record_type
            })
            
        return {
            "status": "success",
            "domain": domain,
            "latency_ms": latency_ms,
            "records": records
        }
        
    except dns.resolver.NXDOMAIN:
        return {"status": "error", "error_type": "NXDOMAIN", "message": "No Record Found", "detail": f"Domain {domain} does not exist."}
    except dns.resolver.NoAnswer:
        return {"status": "error", "error_type": "NoAnswer", "message": "No Record Found", "detail": f"No {record_type} records found for {domain}."}
    except dns.exception.Timeout:
        return {"status": "error", "error_type": "Timeout", "message": "Timeout", "detail": "The DNS query timed out."}
    except Exception as e:
        return {"status": "error", "error_type": "GeneralError", "message": "Resolution Error", "detail": str(e)}
@app.get("/api/whois/{domain}")
async def lookup_whois(domain: str):
    try:
        w = whois.whois(domain)
        # Handle cases where dates might be lists
        def get_iso(date_obj):
            if not date_obj: return None
            if isinstance(date_obj, list): return date_obj[0].isoformat() if hasattr(date_obj[0], 'isoformat') else str(date_obj[0])
            return date_obj.isoformat() if hasattr(date_obj, 'isoformat') else str(date_obj)

        return {
            "status": "success",
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": get_iso(w.creation_date),
            "expiration_date": get_iso(w.expiration_date),
            "name_servers": w.name_servers
        }
    except Exception as e:
        return {"status": "error", "message": "WHOIS Lookup Failed", "detail": str(e)}

@app.get("/api/ssl/{domain}")
async def lookup_ssl(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
        if not cert:
            raise ValueError("No Certificate found")
            
        # Extract issuer details easily
        issuer_name = "Unknown"
        for field in cert.get('issuer', ()):
            for k, v in field:
                if k in ('organizationName', 'commonName'):
                    issuer_name = v
                    break

        return {
            "status": "success",
            "domain": domain,
            "issuer": issuer_name,
            "valid_from": cert.get('notBefore'),
            "valid_to": cert.get('notAfter')
        }
    except Exception as e:
        return {"status": "error", "message": "SSL Check Failed", "detail": str(e)}

@app.get("/api/authenticity/{domain}")
async def lookup_authenticity(domain: str):
    # 1. Check SSL
    has_ssl = False
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                if ssock.getpeercert():
                    has_ssl = True
    except:
        pass

    # 2. Check Age
    age_days = 0
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if isinstance(cd, str): cd = dateutil.parser.parse(cd)
        if hasattr(cd, 'replace'):
            age_days = (datetime.datetime.now().astimezone().replace(tzinfo=None) - cd.replace(tzinfo=None)).days
    except:
        pass
        
    # 3. Check DNSSEC (DS record)
    has_dnssec = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        if resolver.resolve(domain, 'DS'):
            has_dnssec = True
    except:
        pass

    # Verdict
    score = 0
    if has_ssl: score += 50
    if age_days > 365: score += 30
    elif age_days > 30: score += 10
    if has_dnssec: score += 20

    is_authentic = score >= 50
    
    return {
        "status": "success",
        "domain": domain,
        "is_authentic": is_authentic,
        "score": score,
        "metrics": {"has_ssl": has_ssl, "age_days": age_days, "has_dnssec": has_dnssec}
    }
