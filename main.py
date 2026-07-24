import os
import datetime
import requests

print("🚀 1. Iniciando el agente...")

groq_key = os.getenv("GROQ_API_KEY")
webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

def analizar_cve_con_llm(cve_id, descripcion_en, score):
    if not groq_key:
        return f"• **Descripción:** {descripcion_en[:200]}..."

    # Prompt ajustado para estructurar mejor las respuestas
    prompt = f"""
    Actúa como un Analista de Ciberseguridad Sénior. Analiza esta vulnerabilidad crítica y redacta un resumen ejecutivo en español, conciso y profesional.
    
    CVE ID: {cve_id}
    CVSS V3 Score: {score}
    Descripción técnica: {descripcion_en}

    Responde ESTRICTAMENTE con este formato (sin introducciones ni textos extra):
    🎯 **Producto Afectado:** [Software/Plugin y versiones afectadas]
    💥 **Riesgo e Impacto:** [Explicación clara del riesgo técnico y de negocio en 1-2 oraciones]
    🛡️ **Recomendación:** [Acción concreta de mitigación o parcheo]
    """
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {groq_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        data = res.json()
        if res.status_code == 200:
            return data["choices"][0]["message"]["content"].strip()
        else:
            return f"• **Descripción:** {descripcion_en[:200]}..."
    except Exception as e:
        return f"• **Descripción:** {descripcion_en[:200]}..."

# Fechas
now = datetime.datetime.now(datetime.timezone.utc)
yesterday = now - datetime.timedelta(days=1)

pub_start_date = yesterday.strftime("%Y-%m-%dT%H:%M:%S.000")
pub_end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "pubStartDate": pub_start_date,
    "pubEndDate": pub_end_date,
    "cvssV3Severity": "CRITICAL",
    "resultsPerPage": 5
}
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

print("📡 2. Consultando NVD...")

try:
    response = requests.get(NVD_URL, params=params, headers=headers, timeout=15)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        print(f"🔎 Encontradas {len(vulnerabilities)} vulnerabilidades críticas.")

        # --- ENCABEZADO DEL INFORME EJECUTIVO ---
        report = (
            f"📋 **INFORME DIARIO DE CIBERSEGURIDAD | NVD CRITICAL ALERTS**\n"
            f"📅 **Fecha:** {now.strftime('%d/%m/%Y')} | ⚠️ **Filtro:** CVSS >= 9.0 (Crítico)\n"
            f"───────────────────────────────────────────\n\n"
        )

        for idx, vuln in enumerate(vulnerabilities, 1):
            cve_id = vuln['cve']['id']
            descriptions = vuln['cve']['descriptions']
            desc_en = next((d['value'] for d in descriptions if d['lang'] == 'en'), "Sin descripción.")
            
            metrics = vuln['cve'].get('metrics', {})
            cvss_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
            score = cvss_data.get('baseScore', 'N/A')

            print(f"🧠 Procesando {cve_id} con Groq ({idx}/{len(vulnerabilities)})...")
            analisis_ia = analizar_cve_con_llm(cve_id, desc_en, score)

            # --- ESTRUCTURA INDIVIDUAL DE CADA CVE ---
            report += (
                f"`{cve_id}` 🔴 **CVSS {score}**\n"
                f"{analisis_ia}\n"
                f"───────────────────────────────────────────\n"
            )

        if webhook_url:
            print("📤 3. Enviando a Discord...")
            url_limpia = webhook_url.strip().strip('"').strip("'")
            headers_discord = {"Content-Type": "application/json"}
            payload_discord = {"content": report[:1900]}
            
            res = requests.post(url_limpia, json=payload_discord, headers=headers_discord, timeout=10)
            
            if res.status_code in [200, 204]:
                print(f"✅ ¡Informe enviado con éxito a Discord!")
            else:
                print(f"❌ Error al enviar a Discord ({res.status_code}): {res.text}")

except Exception as e:
    print(f"❌ Error general durante la ejecución: {e}")

print("🏁 Fin de la ejecución.")
