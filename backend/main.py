from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import asyncio
import os
from dotenv import load_dotenv
import google.generativeai as genai # Ditambahkan
import json

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # Ganti dengan URL frontend Anda di produksi
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") # Ditambahkan

# Konfigurasi API Gemini (Ditambahkan)
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-1.5-flash') # Atau model lain yang sesuai
else:
    gemini_model = None
    print("PERINGATAN: GEMINI_API_KEY tidak ditemukan. Analisis Gemini akan dilewati.")


class URLRequest(BaseModel):
    url: str

async def get_virustotal_report(client: httpx.AsyncClient, url: str):
    try:
        # Submit URL ke VirusTotal
        post_response = await client.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": VT_API_KEY, "accept": "application/json", "content-type": "application/x-www-form-urlencoded"},
            data=f"url={url}",
            timeout=20.0 # Tambahkan timeout
        )
        post_response.raise_for_status() # Akan raise error jika status code 4xx atau 5xx
        
        url_id_data = post_response.json()
        url_id = url_id_data.get("data", {}).get("id")
        if not url_id:
            return {"error": "Gagal mendapatkan ID URL dari VirusTotal.", "data": None}

        # Tunggu beberapa detik agar VirusTotal sempat memindai (opsional, tapi disarankan untuk URL baru)
        await asyncio.sleep(5) # Perpanjang sedikit waktu tunggu jika diperlukan

        # Dapatkan laporan analisis dari VirusTotal
        report_response = await client.get(
            f"https://www.virustotal.com/api/v3/analyses/{url_id}",
            headers={"x-apikey": VT_API_KEY, "accept": "application/json"},
            timeout=20.0 # Tambahkan timeout
        )
        report_response.raise_for_status()
        return {"error": None, "data": report_response.json()}
    except httpx.RequestError as e:
        return {"error": f"Kesalahan koneksi ke VirusTotal: {str(e)}", "data": None}
    except httpx.HTTPStatusError as e:
        return {"error": f"Kesalahan HTTP dari VirusTotal: {e.response.status_code} - {e.response.text}", "data": None}
    except Exception as e:
        return {"error": f"Kesalahan tak terduga saat menghubungi VirusTotal: {str(e)}", "data": None}

async def get_gemini_analysis(url: str):
    if not gemini_model:
        return {"explanation": "Gemini analysis was skipped because the API key is not configured.", "severity": "Unknown"}

    prompt = f"""
    Analyze the following URL for potential phishing and security risks: "{url}"
    Provide your assessment in JSON format with the following structure:
    {{
      "explanation": "A concise explanation (around 20-50 words) of why this URL is considered (Safe/Suspicious/High Risk/Critical Risk), highlighting specific observations. If it's a common safe URL, state that. If suspicious or risky, mention key indicators observed without being overly verbose.",
      "severity": "A severity level chosen from: 'Safe', 'Low', 'Medium', 'High', 'Critical Risk'."
    }}
    Focus on phishing indicators such as misleading domain names, unusual requests for sensitive information, disguised links, unsolicited communication context, fake urgency, poor grammar/design on the page, or site designs that deceptively mimic official/trusted sites.
    If the URL appears to be a standard login or password reset page for a legitimate and well-known service (e.g., facebook.com, google.com), assess its authenticity.
    If the URL is for a file download, note that and assess based on the URL pattern if possible.
    """
    
    gemini_api_response = None  # Initialize to None
    try:
        gemini_api_response = await gemini_model.generate_content_async(prompt)
        
        if not gemini_api_response or not hasattr(gemini_api_response, 'text'):
             raise ValueError("Received an invalid or empty response from Gemini API.")

        raw_text = gemini_api_response.text.strip()
        
        # Clean potential markdown code block
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        
        analysis_json = await asyncio.to_thread(json.loads, raw_text)
        return analysis_json
        
    except Exception as e:
        error_message = f"Error during Gemini analysis: {str(e)}"
        # Check if gemini_api_response was populated and has text before trying to access it
        if gemini_api_response and hasattr(gemini_api_response, 'text') and gemini_api_response.text:
            print(f"Gemini analysis error: {e}, Raw Gemini response: {gemini_api_response.text}")
            # You might want to include a snippet of the raw response in the error_message for debugging
            # error_message += f" (Raw response snippet: {gemini_api_response.text[:100]})"
        else:
            print(f"Gemini analysis error: {e}. No raw response available or generate_content_async failed.")
        
        return {"explanation": error_message, "severity": "Unknown"}

@app.post("/analyze-url")
async def analyze_url(req: URLRequest):
    url_to_analyze = req.url
    
    # Initialize results to ensure they always have a default value
    virustotal_result_data = {"error": "Analysis not performed", "data": None}
    gemini_analysis_data = {"explanation": "Analysis not performed", "severity": "Unknown"}

    async with httpx.AsyncClient() as client:
        vt_task = get_virustotal_report(client, url_to_analyze)
        gemini_task = get_gemini_analysis(url_to_analyze) # gemini_model check is inside get_gemini_analysis
        
        # Using return_exceptions=True to handle potential errors in each task
        results = await asyncio.gather(vt_task, gemini_task, return_exceptions=True)
        
        # Process VirusTotal result
        if isinstance(results[0], Exception):
            print(f"VirusTotal task raised an exception: {results[0]}")
            virustotal_result_data = {"error": f"VirusTotal analysis failed: {str(results[0])}", "data": None}
        else:
            virustotal_result_data = results[0]

        # Process Gemini result
        if isinstance(results[1], Exception):
            print(f"Gemini task raised an exception: {results[1]}")
            gemini_analysis_data = {"explanation": f"Gemini AI analysis failed: {str(results[1])}", "severity": "Unknown"}
        else:
            gemini_analysis_data = results[1]
            
    # Check if both critical analyses failed before raising a general HTTPException
    if virustotal_result_data.get("error") and gemini_analysis_data.get("explanation", "").endswith("failed.") :
         # Allow partial success if one service responds
         pass # Let the frontend decide how to display partial data

    return {
        "url": url_to_analyze,
        "virustotal": virustotal_result_data,
        "gemini": gemini_analysis_data
    }

@app.get("/")
def read_root():
    return {"message": "Phishing Detector Backend v2 is running"}

# Tambahkan ini di bagian bawah jika ingin menjalankan dengan uvicorn secara langsung (untuk development)
# import uvicorn
# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)