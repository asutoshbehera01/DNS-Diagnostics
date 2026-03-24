import dns.resolver
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
    valid_record_types = ["A", "AAAA", "MX", "CNAME", "TXT", "NS"]
    record_type = type.upper()
    
    if record_type not in valid_record_types:
        raise HTTPException(status_code=400, detail=f"Invalid record type. Supported types: {', '.join(valid_record_types)}")
        
    try:
        # Core Engine: dnspython resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        # Perform the query
        answers = resolver.resolve(domain, record_type)
        
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
