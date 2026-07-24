import os
import datetime
import requests
from openai import OpenAI

# 1. Configurar cliente de OpenAI (espera la clave en la variable de entorno OPENAI_API_KEY)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analizar_cve_con_llm(cve_id, descripcion_en, score):
    """
    Usa OpenAI para generar un análisis estructurado y ejecutivo de la vulnerabilidad.
    """
    prompt = f"""
    Eres un analista experto en ciberseguridad. Analiza la siguiente vulnerabilidad crítica y genera un resumen ejecutivo breve en español.

    CVE ID: {cve_id}
    CVSS Score: {score}
    Descripción técnica original (Inglés): {descripcion_en}

    Por favor responde estrictamente en el siguiente formato (máximo 4 líneas por sección):
    - **Afectado:** [Nombre del software/sistema/hardware afectado]
    - **Impacto:** [Explicación sencilla del riesgo, ej: Ejecución remota de código, bypass de autenticación, etc.]
    - **Mitigación / Acción:** [Recomendación general, ej: Aplicar parche del fabricante, aislar puerto, etc.]
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini", # Puedes usar gpt-4o para mayor precisión
            messages=[
                {"role": "system", "content": "Eres un asistente de inteligencia de amenazas cibernéticas."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"Error llamando a la API de OpenAI: {e}")
        return f"📝 **Descripción:** {descripcion_en[:200]}...\n⚠️ *No se pudo generar el análisis de IA.*"

# 2. Configuración de fechas (últimas 24 horas)
now = datetime.datetime.now(datetime.timezone.utc)
yesterday = now - datetime.timedelta(days=1)

pub_start_date = yesterday.strftime("%Y-%m-%dT%H:%M:%S.000")
pub_end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

# 3. Consulta a la API de NVD
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "pubStartDate": pub_start_date,
    "pubEndDate": pub_end_date,
    "cvssV3Severity": "CRITICAL",
    "resultsPerPage": 10
}

headers = {"User-Agent": "CyberSecurityAgent/1.0"}

print("Consultando vulnerabilidades críticas...")
response = requests.get(NVD_URL, params=params, headers=headers)

if response.status_code != 200:
    print(f"Error al consultar la API de NVD: {response.status_code}")
    exit()

data = response.json()
vulnerabilities = data.get("vulnerabilities", [])

# 4. Construcción del reporte enriquecido con IA
report = f"🚨 **Top {len(vulnerabilities)} Vulnerabilidades Críticas (Resumen IA)** - {now.strftime('%d/%m/%Y')}\n\n"

if not vulnerabilities:
    report += "✅ No se registraron vulnerabilidades críticas en las últimas 24 horas."
else:
    for idx, vuln in enumerate(vulnerabilities, 1):
        cve_id = vuln['cve']['id']
        descriptions = vuln['cve']['descriptions']
        
        # Obtener descripción en inglés para enviarla al LLM
        desc_en = next((d['value'] for d in descriptions if d['lang'] == 'en'), "Sin descripción disponible.")

        # Obtener puntaje CVSS
        metrics = vuln['cve'].get('metrics', {})
        cvss_data = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
        score = cvss_data.get('baseScore', 'N/A')

        print(f"Procesando {cve_id} con LLM...")
        analisis_ia = analizar_cve_con_llm(cve_id, desc_en, score)

        report += f"### {idx}. {cve_id} | Score: {score}\n"
        report += f"{analisis_ia}\n"
        report += f"🔗 [Más información](https://nvd.nist.gov/vuln/detail/{cve_id})\n\n---\n"

# 5. Envío de notificación vía Webhook
WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

if WEBHOOK_URL:
    # Discord acepta mensajes de hasta 2000 caracteres; si el reporte es largo, se puede dividir
    payload = {"content": report[:1900]} 
    requests.post(WEBHOOK_URL, json=payload)
    print("Reporte enviado a Discord/Slack.")
else:
    print("\n--- REPORTE GENERADO EN CONSOLA ---\n")
    print(report)