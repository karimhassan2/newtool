#!/usr/bin/env python3
"""Precision-first hardcoded credential scanner for authorized JS recon.
Normal output is only [FOUND ...] lines. No credential is replayed or verified.
"""
from __future__ import annotations
import argparse,base64,binascii,concurrent.futures,csv,hashlib,json,math,os,re,sys,threading,time,zlib
from collections import deque
from dataclasses import dataclass,field
from pathlib import Path
from typing import Deque,Dict,Iterable,List,Optional,Set,Tuple
from urllib.error import HTTPError,URLError
from urllib.parse import parse_qsl,unquote,urlencode,urljoin,urlparse,urlunparse
from urllib.request import HTTPRedirectHandler,Request,build_opener

UA="Mozilla/5.0 (compatible; ai-secret-scanner/4.1; authorized-assessment)"
TIMEOUT=15
MAX_BYTES=20*1024*1024
THREADS=8
MAX_URLS=0
MAX_DEPTH=3
MIN_ENTROPY=.58
RETRIES=2
RETRY={429,500,502,503,504}
MAX_DECODED=256*1024
MAX_SEGMENTS=2500
ORDER={"critical":0,"high":1,"medium":2,"low":3}
CONF={"high":0,"medium":1,"low":2}
LOCK=threading.Lock()
VERBOSE=False

def log(s,stdout=False,always=False):
    if not always and not VERBOSE:return
    with LOCK:print(s,file=sys.stdout if stdout else sys.stderr,flush=True)

@dataclass(frozen=True)
class Rule:
    name:str
    category:str
    rx:re.Pattern
    confidence:str="high"
    context:Optional[re.Pattern]=None
    group:int=0
    validator:str=""

def kw(s):
    return re.compile("(?i)(?:"+"|".join(re.escape(x) for x in s.split(",") if x)+")")

def strict(data):
    out=[]
    for line in data.strip().splitlines():
        n,c,q,v,p=line.split("\t",4)
        out.append(Rule(n,c,re.compile(p),q,None,0,"" if v=="-" else v))
    return out

def contextual(data):
    out=[]
    for line in data.strip().splitlines():
        n,c,q,k,p=line.split("\t",4)
        out.append(Rule(n,c,re.compile(p),q,kw(k)))
    return out

def structured(data):
    out=[]
    for line in data.strip().splitlines():
        n,c,q,g,v,p=line.split("\t",5)
        out.append(Rule(n,c,re.compile(p),q,None,int(g),"" if v=="-" else v))
    return out

STRICT=strict(r'''
openai	llm	high	-	\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,220}\b
openai_legacy	llm	high	-	\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b
openrouter	llm	high	-	\bsk-or-v1-[A-Fa-f0-9]{64}\b
anthropic	llm	high	-	\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA\b
perplexity	llm	high	-	\bpplx-[A-Za-z0-9]{48}\b
huggingface	llm	high	-	\b(?:hf_[A-Za-z0-9]{34}|api_org_[A-Za-z0-9]{34})\b
groq	llm	high	-	\bgsk_[A-Za-z0-9]{52}\b
replicate	llm	high	-	\br8_[A-Za-z0-9_-]{37}\b
xai	llm	high	-	\bxai-[A-Za-z0-9_]{80}\b
aws_bedrock	llm_cloud	high	-	\bABSK[A-Za-z0-9+/]{109,269}={0,2}
google_api	llm_client_config	medium	-	\bAIza[0-9A-Za-z_-]{35}\b
google_oauth_client_secret	oauth	high	-	\bGOCSPX-[A-Za-z0-9_-]{28}\b
aws_access_key	cloud	high	-	\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b
pinecone	vector	high	-	\bpcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}\b
databricks	llm_data	high	-	(?i)\bdapi[a-f0-9]{32,}\b
salad_cloud	llm_infrastructure	high	-	\bsalad_cloud_[A-Za-z0-9]{1,7}_[A-Za-z0-9]{7,235}\b
sourcegraph_cody	llm_infrastructure	high	-	\bslk_[A-Fa-f0-9]{64}\b
github	vcs	high	-	\bgh[pousr]_[A-Za-z0-9]{36,255}\b
github_fine_grained	vcs	high	-	\bgithub_pat_[A-Za-z0-9_]{60,255}\b
gitlab_pat	vcs	high	-	\bglpat-[A-Za-z0-9_-]{20,255}\b
gitlab_job	vcs	high	-	\bglcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_-]{20}\b
gitlab_deploy	vcs	high	-	\bgldt-[A-Za-z0-9_-]{20}\b
gitlab_feature_flag	vcs	high	-	\bglffct-[A-Za-z0-9_-]{20}\b
gitlab_feed	vcs	high	-	\bglft-[A-Za-z0-9_-]{20}\b
gitlab_incoming_mail	vcs	high	-	\bglimt-[A-Za-z0-9_-]{25}\b
gitlab_agent	vcs	high	-	\bglagent-[A-Za-z0-9_-]{50}\b
gitlab_oauth	vcs	high	-	\bgloas-[A-Za-z0-9_-]{64}\b
gitlab_trigger	vcs	high	-	\bglptt-[A-Fa-f0-9]{40}\b
gitlab_runner	vcs	high	-	\bglrt-[A-Za-z0-9_-]{20}\b
gitlab_scim	vcs	high	-	\bglsoat-[A-Za-z0-9_-]{20}\b
slack_token	chat	high	-	\bxox[baprs]-[A-Za-z0-9-]{10,250}\b
slack_app	chat	high	-	\bxapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+\b
stripe_restricted	payments	high	-	\brk_(?:live|test)_[A-Za-z0-9]{24,255}\b
stripe_or_clerk_secret	auth_payments	high	-	\bsk_(?:live|test)_[A-Za-z0-9]{20,255}\b
stripe_webhook	payments	high	-	\bwhsec_[A-Za-z0-9]{32,255}\b
sendgrid	email	high	-	\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b
npm	registry	high	-	\bnpm_[A-Za-z0-9]{36}\b
pypi	registry	high	-	\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b
rubygems	registry	high	-	\brubygems_[A-Fa-f0-9]{48}\b
clojars	registry	high	-	(?i)\bCLOJARS_[A-Za-z0-9]{60}\b
''')

STRICT+=strict(r'''
mapbox_secret	maps	high	-	\b(?:sk|tk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\b
mapbox_public	client_config	medium	-	\bpk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\b
posthog_secret	analytics	high	-	\bph[xs]_[A-Za-z0-9_-]{20,}\b
posthog_project	client_config	medium	-	\bphc_[A-Za-z0-9_-]{20,}\b
contentful_pat	cms	high	-	\bCFPAT-[A-Za-z0-9_-]{40,}\b
notion	productivity	high	-	\bntn_[0-9]{11}[A-Za-z0-9]{35}\b
linear	productivity	high	-	(?i)\blin_api_[A-Za-z0-9]{40}\b
planetscale	database	high	-	(?i)\bpscale_(?:tkn|oauth|pw)_[A-Za-z0-9=._-]{32,}\b
doppler	secrets	high	-	(?i)\bdp\.pt\.[A-Za-z0-9]{43}\b
figma	design	high	-	\bfigd_[A-Za-z0-9_-]{40,}\b
new_relic_user	monitoring	high	-	(?i)\bNRAK-[A-Za-z0-9]{27}\b
new_relic_insert	monitoring	high	-	(?i)\bNRII-[A-Za-z0-9-]{32}\b
new_relic_browser	client_config	medium	-	(?i)\bNRJS-[A-Fa-f0-9]{19}\b
cloudflare_origin_ca	cloud	high	-	\bv1\.0-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{146}\b
digitalocean	cloud	high	-	\bdop_v1_[A-Fa-f0-9]{64}\b
digitalocean_refresh	cloud	high	-	\bdor_v1_[A-Fa-f0-9]{64}\b
shopify	commerce	high	-	\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}\b
grafana	monitoring	high	-	\bgl(?:c|sa)_[A-Za-z0-9_-]{20,}\b
sentry_secret	monitoring	high	-	\bsntrys_[A-Za-z0-9_-]{20,}\b
dockerhub	registry	high	-	\bdckr_pat_[A-Za-z0-9_-]{20,}\b
sonar	code_quality	high	-	\bsqu_[A-Za-z0-9]{40}\b
vercel	cloud	high	-	\b(?:vcp|vca)_[A-Za-z0-9_-]{20,}\b
airtable	data	high	-	\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}\b
square	payments	high	-	\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b
mailgun	email	high	-	\bkey-[A-Fa-f0-9]{32}\b
sendinblue	email	high	-	\bxkeysib-[A-Fa-f0-9]{64}-[A-Za-z0-9]{16}\b
onepassword_secret_key	secrets	high	-	\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b
onepassword_service_account	secrets	high	-	\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}
age_secret_key	crypto	high	-	\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b
adobe_client_secret	cloud	high	-	(?i)\bp8e-[A-Za-z0-9]{32}\b
alibaba_access_key	cloud	high	-	(?i)\bLTAI[A-Za-z0-9]{20}\b
artifactory_api_key	registry	high	-	\bAKCp[A-Za-z0-9]{69}\b
atlassian_api_token	productivity	high	-	\bATATT3[A-Za-z0-9_=-]{186}\b
authress	auth	high	-	\b(?:sc|ext|scauth|authress)_[A-Za-z0-9]{5,30}\.[A-Za-z0-9]{4,6}\.acc[_-][A-Za-z0-9-]{10,32}\.[A-Za-z0-9+/_=-]{30,120}
azure_ad_client_secret	cloud	high	-	\b[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b
dropbox_short_lived	storage	high	-	\bsl\.[A-Za-z0-9=_-]{135}\b
dynatrace	monitoring	high	-	(?i)\bdt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}\b
easypost_live	shipping	high	-	(?i)\bEZAK[A-Za-z0-9]{54}\b
easypost_test	shipping	high	-	(?i)\bEZTK[A-Za-z0-9]{54}\b
flyio	cloud	high	-	\b(?:fo1_[A-Za-z0-9_-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3})
vault_batch	secrets	high	-	\bhvb\.[A-Za-z0-9_-]{138,300}\b
vault_service	secrets	high	-	\bhvs\.[A-Za-z0-9_-]{90,120}\b
heroku_v2	cloud	high	-	\bHRKU-AA[A-Za-z0-9_-]{58}\b
postman	api	high	-	\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}\b
prefect	automation	high	-	\bpnu_[A-Za-z0-9]{36}\b
pulumi	cloud	high	-	\bpul-[A-Fa-f0-9]{40}\b
readme	documentation	high	-	(?i)\brdme_[A-Za-z0-9]{70}\b
sourcegraph	code_search	high	-	\b(?:sgp_(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40}|sgp_[A-Fa-f0-9]{40})\b
terraform_cloud	cloud	high	-	(?i)\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9=_-]{60,70}\b
supabase_secret	database	high	-	\bsb_secret_[A-Za-z0-9_-]{20,}\b
supabase_pat	database	high	-	\bsbp_[A-Za-z0-9_-]{20,}\b
tailscale	network	high	-	\btskey-(?:api|auth)-[A-Za-z0-9_-]{20,}\b
discord_bot	chat	high	-	\b(?:M|N|O)[A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b
telegram_bot	chat	medium	-	\b\d{8,10}:[A-Za-z0-9_-]{35}\b
paseto	token	high	paseto	\bv[1-4]\.(?:local|public)\.[A-Za-z0-9_-]{40,}(?:\.[A-Za-z0-9_-]+)?\b
jwe	token	high	jwe	\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b
jwt	token	high	jwt	\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.(?:[A-Za-z0-9_-]{5,})?\b
slack_webhook	webhook	high	-	https://hooks\.slack\.com/(?:services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25}|workflows/T[A-Z0-9]+/A[A-Z0-9]+/\d{17,19}/[A-Za-z0-9]{23,25}|triggers/[A-Za-z0-9+/]{43,56})
discord_webhook	webhook	high	-	https?://(?:discord|discordapp)\.com/api/webhooks/\d{18,19}/[A-Za-z0-9_-]{60,80}
tines_webhook	webhook	high	-	https://[A-Za-z0-9-]+\.tines\.com/webhook/[A-Fa-f0-9]{32}/[A-Fa-f0-9]{32}
teams_webhook	webhook	high	-	https?://[A-Za-z0-9.-]*(?:webhook\.office\.com|webhook\.office365\.com)/webhookb2/[A-Za-z0-9@._/%?=&+-]{40,}
private_key_pem	crypto	high	private	-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]{80,20000}?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----
pgp_private_key	crypto	high	private	-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{80,50000}?-----END PGP PRIVATE KEY BLOCK-----
''')

CONTEXT=contextual(r'''
cohere	llm	medium	cohere,co_api_key,cohere_api_key,api.cohere.ai	\b[A-Za-z0-9]{40}\b
mistral	llm	medium	mistral_api_key,api.mistral.ai,mistral	\b[A-Za-z0-9]{32}\b
deepseek	llm	high	deepseek_api_key,api.deepseek.com,deepseek	\bsk-[A-Za-z0-9]{32}\b
together	llm	medium	together_api_key,api.together.xyz,togetherai	\b[A-Fa-f0-9]{64}\b
cerebras	llm	medium	cerebras_api_key,api.cerebras.ai,cerebras	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
fireworks_ai	llm	medium	fireworks_api_key,api.fireworks.ai,fireworks.ai	\bsk-[A-Za-z0-9_-]{20,128}\b
stability_ai	llm	medium	stability_api_key,api.stability.ai,stability.ai	\bsk-[A-Za-z0-9_-]{20,128}\b
ai21	llm	medium	ai21_api_key,ai21_token,api.ai21.com,ai21labs	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
assemblyai	llm_audio	medium	assemblyai_api_key,assembly_api_key,aai_api_key,api.assemblyai.com	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
elevenlabs	llm_audio	medium	elevenlabs,eleven_labs,xi-api-key,api.elevenlabs.io	\b[A-Fa-f0-9]{32}\b
deepgram	llm_audio	medium	deepgram_api_key,api.deepgram.com,deepgram	\b[A-Za-z0-9]{40}\b
voyage_ai	llm	medium	voyage_api_key,voyageai_api_key,api.voyageai.com	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
jina_ai	llm	medium	jina_api_key,api.jina.ai,jina.ai	\bjina_[A-Za-z0-9_-]{20,128}\b
langsmith	llm_observability	medium	langsmith_api_key,langchain_api_key,api.smith.langchain.com,langsmith	\b(?:lsv2_|ls__)[A-Za-z0-9_-]{20,128}\b
helicone	llm_observability	medium	helicone_api_key,helicone-auth,helicone.ai	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
azure_openai	llm_cloud	medium	azure_openai_api_key,openai_api_key,.openai.azure.com	\b[A-Fa-f0-9]{32}\b
nvidia_ngc	llm_infrastructure	medium	ngc_api_key,nvidia_api_key,integrate.api.nvidia.com,nvapi-	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
cloudflare_ai	llm_cloud	medium	cloudflare_api_token,cf_api_token,api.cloudflare.com,workers ai	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
weaviate	vector	medium	weaviate_api_key,authentication_apikey_allowed_keys,weaviate.auth.api_key	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
qdrant	vector	medium	qdrant_api_key,qdrant__service__api_key,qdrant.tech	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
privateai	llm_privacy	medium	privateai,private_ai,private-ai	\b[A-Fa-f0-9]{32}\b
mui_license	license	medium	materialuilicense,material_ui_license,mui_license,setlicensekey,x-license	(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{80,240}(?![A-Za-z0-9+/=_-])
surfly	widget	medium	surfly,surflykey,surfly_key	\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12})\b
contentful_delivery	cms	medium	contentful,contentful_access_token,previewaccesstoken,cda_token	(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])
algolia	search	medium	algolia,adminapikey,searchonlyapikey	\b[A-Fa-f0-9]{32}\b
datadog	monitoring	medium	datadog,dd_api_key,dd_app_key	\b[A-Fa-f0-9]{32,40}\b
auth0_client_secret	auth	medium	auth0,auth0_client_secret,clientsecret	(?<![A-Za-z0-9_~.+/=-])[A-Za-z0-9_~.+/=-]{24,256}(?![A-Za-z0-9_~.+/=-])
okta	auth	medium	okta,okta_token,apitoken	\b00[A-Za-z0-9_-]{38,50}\b
twilio	comms	medium	twilio,twilio_api_key,authtoken	\bSK[A-Fa-f0-9]{32}\b
aws_secret_access_key	cloud	medium	aws_secret_access_key,secretaccesskey,awssecret	\b[A-Za-z0-9/+=]{40}\b
azure_storage_key	cloud	medium	accountkey,azure_storage,storageaccountkey	\b[A-Za-z0-9+/]{86}==\b
''')

STRUCT=structured(r'''
authorization_bearer	auth	high	1	-	(?ix)(?:authorization|proxy[-_]?authorization)\s*["'`]?\s*[:=]\s*["'`]\s*(?:bearer|token)\s+([A-Za-z0-9_~.+/=-]{16,500})["'`]
authorization_basic	auth	high	1	basic	(?ix)(?:authorization|proxy[-_]?authorization)\s*["'`]?\s*[:=]\s*["'`]\s*basic\s+([A-Za-z0-9+/]{8,}={0,3})["'`]
hardcoded_api_header	auth	medium	1	-	(?ix)(?:x[-_]?api[-_]?key|api[-_]?key|x[-_]?auth[-_]?token|x[-_]?access[-_]?token|x[-_]?client[-_]?secret|helicone[-_]?auth)\s*["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_~.+/=-]{16,300})["'`]
hardcoded_named_secret	secret	medium	1	-	(?ix)(?:oauth[_-]?client[_-]?secret|client[_-]?secret|jwt[_-]?secret|session[_-]?secret|cookie[_-]?secret|signing[_-]?(?:key|secret)|encryption[_-]?key|webhook[_-]?secret|refresh[_-]?token)\s*["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_~.+/=-]{20,512})["'`]
database_uri_password	database	high	1	-	(?ix)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis(?:s)?|amqp(?:s)?|mssql|sqlserver|snowflake|neo4j(?:\+s)?|bolt(?:\+s)?|kafka)://[^:@/\s"'`]{1,128}:([^@/\s"'`]{3,256})@[^\s"'`]{1,512}
elastic_uri_password	database	high	1	-	(?ix)\bhttps?://[^:@/\s"'`]{1,128}:([^@/\s"'`]{3,256})@[^\s"'`]*(?:elastic|opensearch)[^\s"'`]*
url_basic_password	auth	medium	1	-	(?ix)\bhttps?://[^:@/\s"'`]{1,128}:([^@/\s"'`]{3,256})@[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[^\s"'`]*)?
azure_redis_password	database	high	1	-	(?ix)\b[A-Za-z0-9.-]+\.redis\.cache\.windows\.net:6380,password=([^,\s"'`]{20,100}),ssl=true,abortconnect=false
google_refresh_token	oauth	high	1	-	(?ix)(?:refresh[_-]?token|google[_-]?refresh[_-]?token)\s*["'`]?\s*[:=]\s*["'`](1//[A-Za-z0-9_-]{20,300})["'`]
azure_sas_signature	cloud	high	1	-	(?ix)(?:\?|&|["'`])sv=\d{4}-\d{2}-\d{2}[^\s"'`]{0,1500}?[&]sig=([A-Za-z0-9%+/=_-]{20,300})(?:[&"'`\s]|$)
aws_presigned_signature	cloud	high	1	-	(?ix)X-Amz-Algorithm=AWS4-HMAC-SHA256[^\s"'`]{0,2000}?[&]X-Amz-Signature=([A-Fa-f0-9]{64})(?:[&"'`\s]|$)
''')

GENERIC=re.compile(r'''(?ix)(?P<n>[\w.-]{0,60}(?:api[_-]?key|secret|token|access[_-]?key|client[_-]?secret|authorization|bearer))\s*[:=]\s*["'](?P<v>[A-Za-z0-9_~./+\-=]{20,256})["']''')
CONCAT=re.compile(r'''(?:["'](?:\\.|[^"'\\]){1,128}["']\s*\+\s*)+["'](?:\\.|[^"'\\]){1,128}["']''')
ATOB=re.compile(r'''\batob\(\s*["']([A-Za-z0-9+/_-]{16,}={0,2})["']\s*\)''')
URI=re.compile(r'''\bdecodeURIComponent\(\s*["']([^"']{16,4096})["']\s*\)''')
CHARS=re.compile(r'''\bString\.fromCharCode\(\s*(\d{1,3}(?:\s*,\s*\d{1,3}){7,511})\s*\)''')
B64=re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_-])")
SCRIPT=re.compile(r'''<script[^>]+src=["']([^"']+)["']''',re.I)
JSLINK=re.compile(r'''["']([^"'\s]{1,500}\.(?:js|mjs)(?:\?[^"']*)?)["']''',re.I)
MAPREF=re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
INMAP=re.compile(r"//[#@]\s*sourceMappingURL=data:application/json(?:;charset=[^;,]+)?;base64,([^\s]+)")
PEM=re.compile(r"-----BEGIN (?P<t>[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----(?P<b>[\s\S]+?)-----END (?P=t)-----")
PLACE={"true","false","null","undefined","none","password","secret","token","apikey","api_key","test","testing","development","example","placeholder","changeme","change_me","replace_me","dummy","sample","lorem","your_key","your_token","your_secret","your_api_key","insert_key_here","replace_with_your_key"}
PH=re.compile(r"(?i)^(?:your|example|placeholder|changeme|change_me|replace_me|dummy|sample|lorem|insert)(?:[-_.]?(?:api[-_.]?)?(?:key|token|secret|password|value|here))*$")
PATHLIKE=re.compile(r"^[./]|://|\.(?:js|mjs|css|png|jpe?g|gif|svg|woff2?|ttf|map|html?|json|xml|txt)\b",re.I)
HASH=re.compile(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})",re.I)
JWTALG={"none","HS256","HS384","HS512","RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512","ES256K","EdDSA"}
JWEALG={"dir","RSA1_5","RSA-OAEP","RSA-OAEP-256","A128KW","A192KW","A256KW","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A192KW","ECDH-ES+A256KW","A128GCMKW","A192GCMKW","A256GCMKW","PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"}
JWEENC={"A128GCM":(12,16),"A192GCM":(12,16),"A256GCM":(12,16),"A128CBC-HS256":(16,16),"A192CBC-HS384":(16,24),"A256CBC-HS512":(16,32)}

def placeholder(v):
    try:v=unquote(v)
    except (TypeError,ValueError):pass
    v=v.strip().strip("\"'`")
    l=v.lower()
    return not v or l in PLACE or bool(
        PH.fullmatch(v)
        or re.search(r"\$\{[^}]+\}|\{\{[^}]+\}|<[\w-]+>",v)
        or re.fullmatch(r"(?:[xX*._-]{6,}|0{12,}|1{12,}|A{16,}|a{16,}|B{16,}|b{16,})",v)
    )

def entropy(v):
    if not v:return 0
    n=len(v)
    d={}
    for x in v:d[x]=d.get(x,0)+1
    h=-sum((c/n)*math.log2(c/n) for c in d.values())
    a=(26 if re.search('[a-z]',v) else 0)+(26 if re.search('[A-Z]',v) else 0)+(10 if re.search(r'\d',v) else 0)+(10 if re.search(r'\W',v) else 0)
    return h/math.log2(max(a,2))

def quality(v,m=MIN_ENTROPY):
    return not placeholder(v) and len(set(v))>=6 and entropy(v)>=m

def probable(v,m=.62):
    return (
        len(v)>=20
        and quality(v,m)
        and not PATHLIKE.search(v)
        and not HASH.fullmatch(v)
        and (bool(re.search(r'\d',v)) or bool(re.search(r'[+/=_.-]',v)))
    )

def b64u(v):
    if not re.fullmatch(r"[A-Za-z0-9_-]*",v):return None
    try:return base64.urlsafe_b64decode((v+"="*(-len(v)%4)).encode())
    except (ValueError,binascii.Error):return None

def b64json(v):
    x=b64u(v)
    if x is None or len(x)>131072:return None
    try:
        y=json.loads(x.decode())
        return y if isinstance(y,dict) else None
    except (UnicodeDecodeError,json.JSONDecodeError):
        return None

def jwt(v):
    p=v.split('.')
    if len(p)!=3 or not p[0] or not p[1]:return False
    h,d=b64json(p[0]),b64json(p[1])
    alg=h.get('alg') if h else None
    if not isinstance(alg,str) or d is None or alg not in JWTALG:return False
    if alg=='none':return p[2]==''
    s=b64u(p[2])
    return s is not None and len(s)>=16

def jwe(v):
    p=v.split('.')
    if len(p)!=5 or not p[0] or not all(p[i] for i in (2,3,4)):return False
    h=b64json(p[0])
    alg=h.get('alg') if h else None
    enc=h.get('enc') if h else None
    if not isinstance(alg,str) or not isinstance(enc,str) or alg not in JWEALG or enc not in JWEENC:return False
    k,iv,ct,tag=map(b64u,p[1:])
    direct=alg in {'dir','ECDH-ES'}
    if None in (k,iv,ct,tag) or (direct and k) or (not direct and not k):return False
    a,b=JWEENC[enc]
    return len(iv)==a and bool(ct) and len(tag)==b

def paseto(v):
    p=v.split('.')
    if len(p) not in (3,4) or p[0] not in {'v1','v2','v3','v4'} or p[1] not in {'local','public'}:return False
    mins={
        ('v1','local'):80,
        ('v2','local'):40,
        ('v3','local'):80,
        ('v4','local'):64,
        ('v1','public'):256,
        ('v2','public'):64,
        ('v3','public'):96,
        ('v4','public'):64
    }
    x=b64u(p[2])
    f=b64u(p[3]) if len(p)==4 else b''
    return x is not None and len(x)>=mins[p[0],p[1]] and f is not None

def basic(v):
    try:x=base64.b64decode(v,validate=True).decode()
    except (ValueError,UnicodeDecodeError,binascii.Error):return False
    if ':' not in x:return False
    u,p=x.split(':',1)
    return bool(u and p and not placeholder(p) and len(set(p))>=4)

def private(v):
    m=PEM.search(v.replace('\\r','').replace('\\n','\n'))
    if not m:return False
    e=''.join(
        x.strip()
        for x in m.group('b').splitlines()
        if x.strip() and ':' not in x and not x.lstrip().startswith('=')
    )
    try:r=base64.b64decode(e,validate=True)
    except (ValueError,binascii.Error):return False
    if m.group('t')=='OPENSSH PRIVATE KEY':
        return r.startswith(b'openssh-key-v1\0')
    if m.group('t')=='PGP PRIVATE KEY BLOCK':
        return len(r)>=64 and bool(r[0]&128)
    return len(r)>=48 and r.startswith(b'0')

VALID={'jwt':jwt,'jwe':jwe,'paseto':paseto,'basic':basic,'private':private}

STRUCT += [
    Rule(
        "jwk_private_component",
        "crypto",
        re.compile(r'''(?ix)["']d["']\s*:\s*["']([A-Za-z0-9_-]{43,1400})["']'''),
        "high",
        kw('"kty",\'kty\',"private",\'private\''),
        1
    ),
    Rule(
        "google_service_account_private_key",
        "cloud",
        re.compile(r'''(?is)["']type["']\s*:\s*["']service_account["'].{0,12000}?["']private_key["']\s*:\s*["']((?:\\.|[^"']){100,10000}?-----END PRIVATE KEY-----)["']'''),
        "high",
        None,
        1,
        "private"
    )
]

ARR=re.compile(r'''\[(?P<i>\s*["'](?:\\.|[^"'\\])*["'](?:\s*,\s*["'](?:\\.|[^"'\\])*["']){1,31}\s*)\]\.join\(\s*["'](?P<s>(?:\\.|[^"'\\])*)["']\s*\)''')
TEMPLATE=re.compile(r"`(?P<b>(?:\\.|[^`\\]){1,2048})`")
TPART=re.compile(r'''\$\{\s*(?:["'](?P<s>(?:\\.|[^"'\\])*)["']|(?P<n>\d+))\s*\}''')
ESCAPED=re.compile(r"(?:(?:\\x[0-9A-Fa-f]{2})|(?:\\u[0-9A-Fa-f]{4})|(?:\\u\{[0-9A-Fa-f]{1,6}\})){6,}")

def allowed(r,v,m=MIN_ENTROPY):
    if not v or placeholder(v):return False
    if r.validator:
        try:
            if not VALID[r.validator](v):return False
        except Exception:
            return False
    if r.category=='crypto':return True
    if r in CONTEXT and (PATHLIKE.search(v) or not quality(v,max(.5,m))):return False
    if r.name in {'authorization_bearer','hardcoded_api_header'} and not probable(v,.5):return False
    if r.confidence!='high' and not quality(v,m):return False
    return len(set(re.sub(r'\W','',v)))>=6

def unesc(v):
    try:
        v=re.sub(r'\\x([0-9a-fA-F]{2})',lambda m:chr(int(m[1],16)),v)
        v=re.sub(r'\\u\{([0-9a-fA-F]{1,6})\}',lambda m:chr(int(m[1],16)),v)
        v=re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),v)
    except (ValueError,OverflowError):
        return None
    d={'n':'\n','r':'\r','t':'\t','b':'\b','f':'\f','v':'\v','\\':'\\',"'":"'",'"':'"','`':'`'}
    return re.sub(r'''\\([nrtbfv\\'"`])''',lambda m:d[m[1]],v)

def qparts(v):
    a=[]
    for m in re.finditer(r'''(["'])((?:\\.|(?!\1).)*)\1''',v):
        x=unesc(m[2])
        if x is None:return None
        a.append(x)
    return a or None

def printable(x):
    try:s=x.decode()
    except UnicodeDecodeError:return None
    return s if s and len(s)<=MAX_DECODED and sum(c.isprintable() or c in '\r\n\t' for c in s)/len(s)>=.88 else None

def transformed(text):
    seen=set()
    count=0

    def emit(label,m,x):
        nonlocal count
        if not x or x in seen or len(x)>MAX_DECODED or count>=MAX_SEGMENTS:return None
        seen.add(x)
        count+=1
        return label,text[max(0,m.start()-240):m.start()]+x+text[m.end():min(len(text),m.end()+240)]

    for m in B64.finditer(text):
        for label,fn in [('base64',base64.b64decode),('base64url',base64.urlsafe_b64decode)]:
            try:x=emit(label,m,printable(fn((m[0]+'='*(-len(m[0])%4)).encode())))
            except (ValueError,binascii.Error):x=None
            if x:yield x

    for m in CONCAT.finditer(text):
        p=qparts(m[0])
        x=emit('literal_concatenation',m,''.join(p) if p else None)
        if x:yield x

    for m in ARR.finditer(text):
        p=qparts(m['i'])
        sep=unesc(m['s'])
        x=emit('array_join',m,sep.join(p) if p and sep is not None else None)
        if x:yield x

    for m in ATOB.finditer(text):
        try:x=emit('atob',m,printable(base64.b64decode((m[1]+'='*(-len(m[1])%4)).encode())))
        except (ValueError,binascii.Error):x=None
        if x:yield x

    for m in URI.finditer(text):
        x=emit('decode_uri_component',m,unquote(m[1]))
        if x:yield x

    for m in CHARS.finditer(text):
        try:
            a=[int(i) for i in m[1].split(',')]
            x=emit('from_char_code',m,''.join(chr(i) for i in a) if all(0<=i<256 for i in a) else None)
        except (ValueError,OverflowError):
            x=None
        if x:yield x

    for m in TEMPLATE.finditer(text):
        b=m['b']
        cur=0
        a=[]
        ok=True
        for p in TPART.finditer(b):
            z=b[cur:p.start()]
            if '${' in z:
                ok=False
                break
            w=unesc(p['s'] if p['s'] is not None else p['n'])
            if w is None:
                ok=False
                break
            a+=[z,w]
            cur=p.end()
        if '${' in b[cur:]:ok=False
        if ok and cur:
            a.append(b[cur:])
            x=emit('template_literal',m,unesc(''.join(a)))
            if x:yield x

    for m in ESCAPED.finditer(text):
        x=emit('escaped_literal',m,unesc(m[0]))
        if x:yield x

def assigned(t,a,b):
    return (
        a>0
        and b<len(t)
        and t[a-1] in "\"'`"
        and t[b]==t[a-1]
        and bool(re.search(r'''(?:[:=,(]|=>)\s*["'`]?$''',t[max(0,a-180):a]))
    )

def sev(r):
    critical={
        'openai','openai_legacy','openrouter','anthropic','aws_bedrock',
        'aws_access_key','github','github_fine_grained','private_key_pem',
        'pgp_private_key','google_service_account_private_key',
        'stripe_restricted','stripe_or_clerk_secret'
    }
    if r.confidence=='high' and r.name in critical:return 'critical'
    if r.category.endswith('client_config'):return 'medium'
    return 'high' if r.confidence=='high' else 'medium'

def clean_url(u):
    try:
        p=urlparse(u)
        if p.scheme not in ('http','https') or not p.hostname:return u
        h=p.hostname
        host=f'[{h}]' if ':' in h else h
        try:port=p.port
        except ValueError:port=None
        netloc=host+(f':{port}' if port else '')
        q=[]
        sensitive=re.compile(
            r'(?i)(?:^|[_-])(?:key|api[_-]?key|access[_-]?(?:key|token)|'
            r'auth|authorization|credential|jwt|password|secret|signature|sig|token|'
            r'x-amz-(?:credential|security-token|signature)|'
            r'x-goog-(?:credential|signature))(?:$|[_-])'
        )
        for k,v in parse_qsl(p.query,keep_blank_values=True):
            q.append((k,'REDACTED' if sensitive.search(k) else v))
        return urlunparse((p.scheme,netloc,p.path,p.params,urlencode(q),''))
    except (TypeError,ValueError):
        return '[invalid-url]'

def lc(t,n):
    a=t.count('\n',0,n)+1
    b=t.rfind('\n',0,n)
    return a,n+1 if b<0 else n-b

def red(v):
    v=v.replace(chr(13),'').replace(chr(10),'\\n')
    if len(v)<=12:return v[:2]+'[redacted]'
    return v[:4]+'...[redacted] (len='+str(len(v))+')'

def snippet(t,a,b):
    x=t[max(0,a-42):a]+'«TOKEN»'+t[b:min(len(t),b+42)]
    return re.sub(
        r'\s+',
        ' ',
        re.sub(r'[A-Za-z0-9_~.+/=-]{20,}','«REDACTED»',x)
    ).strip()[:180]

@dataclass
class Finding:
    provider:str
    category:str
    confidence:str
    severity:str
    source:str
    line:Optional[int]
    column:Optional[int]
    transform:str
    context:str
    redacted:str
    finding_id:str
    token:str=field(default='',repr=False)

    def record(self,full=False):
        x={
            'finding_id':self.finding_id,
            'severity':self.severity,
            'confidence':self.confidence,
            'provider':self.provider,
            'category':self.category,
            'source':self.source,
            'line':self.line,
            'column':self.column,
            'transform':self.transform,
            'redacted':self.redacted,
            'context':self.context
        }
        if full:x['token']=self.token
        return x

@dataclass
class Config:
    scope:List[str]
    threads:int=THREADS
    timeout:int=TIMEOUT
    max_bytes:int=MAX_BYTES
    max_urls:int=MAX_URLS
    max_depth:int=MAX_DEPTH
    min_entropy:float=MIN_ENTROPY
    follow:bool=True
    decode:bool=True
    generic:bool=False

@dataclass
class Fetched:
    url:str
    text:str
    ctype:str

def scan(text,source,cfg,kind='raw'):
    seg=[(kind,text)]+(list(transformed(text)) if cfg.decode else [])
    found=[]

    for tag,t in seg:
        for r in STRICT+CONTEXT+STRUCT:
            if r.context and not r.context.search(t):continue

            for m in r.rx.finditer(t):
                try:
                    v=m.group(r.group)
                    a=m.start(r.group)
                    b=m.end(r.group)
                except (IndexError,AttributeError):
                    continue

                around=t[max(0,a-220):min(len(t),b+220)]

                if r in CONTEXT and (
                    not r.context.search(around)
                    or not assigned(t,a,b)
                ):
                    continue

                if r in STRUCT and r.context and not r.context.search(around):
                    continue

                if allowed(r,v):
                    found.append((r,v,t,a,b,tag))

        if cfg.generic:
            for m in GENERIC.finditer(t):
                if probable(m['v']):
                    found.append((
                        Rule('generic:'+m['n'][-36:],'generic',GENERIC,'medium'),
                        m['v'],t,m.start('v'),m.end('v'),tag
                    ))

    best={}
    for x in found:
        if x[1] not in best or CONF[x[0].confidence]<CONF[best[x[1]][0].confidence]:
            best[x[1]]=x

    out=[]
    for r,v,t,a,b,tag in best.values():
        line,col=lc(t,a) if tag in {'raw','map','source','inline_map'} else (None,None)
        src=clean_url(source)
        out.append(Finding(
            r.name,
            r.category,
            r.confidence,
            sev(r),
            src,
            line,
            col,
            tag,
            snippet(t,a,b),
            red(v),
            hashlib.sha256((source+'\0'+v).encode()).hexdigest()[:16],
            v
        ))

    return out

def host_scope(x):
    x=x.strip().lower()
    wild=x.startswith('*.')
    x=x[2:] if wild else x

    if '://' in x:
        try:x=urlparse(x).hostname or ''
        except ValueError:return ''
    elif x.startswith('[') and ']' in x:
        x=x[1:x.index(']')]
    elif x.count(':')<2:
        x=x.split('/',1)[0].split(':',1)[0]

    x=x.rstrip('.')
    return '*.'+x if wild and x else x

def in_scope(u,cfg):
    try:
        p=urlparse(u)
        if p.scheme.lower() not in ('http','https'):return False
        h=(p.hostname or '').lower().rstrip('.')
    except ValueError:
        return False

    for s in cfg.scope:
        s=host_scope(s)
        if s.startswith('*.') and (h==s[2:] or h.endswith('.'+s[2:])):
            return True
        if h==s:
            return True

    return False

def canon(u):
    try:
        p=urlparse(u)
        return urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            p.path or '/',
            p.params,
            p.query,
            ''
        ))
    except ValueError:
        return u

class ScopedRedirect(HTTPRedirectHandler):
    def __init__(self,cfg):
        self.cfg=cfg

    def redirect_request(self,req,fp,code,msg,headers,newurl):
        if not in_scope(newurl,self.cfg):
            raise URLError('redirect left authorized scope')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def inflate(raw,enc,limit):
    if not enc:return raw
    w=16+zlib.MAX_WBITS if 'gzip' in enc else zlib.MAX_WBITS

    try:
        d=zlib.decompressobj(w)
        out=d.decompress(raw,limit+1)

        if d.unconsumed_tail or len(out)>limit:
            raise ValueError('expanded response exceeds limit')

        out+=d.flush(max(0,limit+1-len(out)))

        if len(out)>limit:
            raise ValueError('expanded response exceeds limit')

        return out
    except zlib.error as e:
        raise ValueError('invalid compressed response') from e

def fetch(u,cfg):
    if not in_scope(u,cfg):return None
    op=build_opener(ScopedRedirect(cfg))
    safe=clean_url(u)

    for n in range(RETRIES+1):
        try:
            q=Request(u,headers={
                'User-Agent':UA,
                'Accept':'text/html,application/javascript,text/javascript,application/json,text/plain,*/*;q=.1',
                'Accept-Encoding':'gzip,deflate'
            })

            with op.open(q,timeout=cfg.timeout) as r:
                final=r.geturl()

                if not in_scope(final,cfg):
                    raise URLError('response left authorized scope')

                size=r.headers.get('Content-Length')

                if size and cfg.max_bytes and int(size)>cfg.max_bytes:
                    raise ValueError('response exceeds limit')

                raw=r.read(cfg.max_bytes+1 if cfg.max_bytes else -1)

                if cfg.max_bytes and len(raw)>cfg.max_bytes:
                    raise ValueError('response exceeds limit')

                raw=inflate(
                    raw,
                    (r.headers.get('Content-Encoding') or '').lower(),
                    cfg.max_bytes or MAX_BYTES
                )

                ct=r.headers.get_content_type()
                cs=r.headers.get_content_charset() or 'utf-8'

                try:text=raw.decode(cs)
                except (LookupError,UnicodeDecodeError):
                    text=raw.decode('utf-8','replace')

                return Fetched(canon(final),text,ct)

        except HTTPError as e:
            if e.code not in RETRY or n==RETRIES:
                log(f'[SKIP] {safe}: HTTP {e.code}')
                return None

        except (URLError,ValueError,OSError) as e:
            if n==RETRIES:
                log(f'[SKIP] {safe}: {e}')
                return None

        time.sleep(.4*(2**n))

    return None

def text_json(t):
    t=t.lstrip('\ufeff\n\r\t ')

    if t.startswith(")]}'"):
        t=t.split('\n',1)[-1]

    try:
        x=json.loads(t)
        return x if isinstance(x,dict) else None
    except json.JSONDecodeError:
        return None

def data_map(ref):
    if not ref.startswith('data:') or ',' not in ref:return None
    head,payload=ref.split(',',1)

    try:
        raw=(
            base64.b64decode(payload,validate=True)
            if ';base64' in head.lower()
            else unquote(payload).encode()
        )

        if len(raw)>MAX_DECODED*16:return None
        return text_json(raw.decode('utf-8'))

    except (ValueError,UnicodeDecodeError,binascii.Error):
        return None

def map_parts(obj):
    yield obj

    for sec in obj.get('sections',[]) if isinstance(obj.get('sections'),list) else []:
        if isinstance(sec,dict) and isinstance(sec.get('map'),dict):
            yield from map_parts(sec['map'])

def map_content(obj,origin,cfg):
    out=[]
    urls=[]

    for part in map_parts(obj):
        src=part.get('sources')
        body=part.get('sourcesContent')
        root=part.get('sourceRoot','')

        if not isinstance(src,list):continue
        body=body if isinstance(body,list) else []

        for i,name in enumerate(src):
            content=body[i] if i<len(body) else None

            if isinstance(content,str):
                out+=scan(
                    content,
                    clean_url(origin)+f'#source-{i+1}',
                    cfg,
                    'source'
                )

            elif isinstance(name,str):
                u=urljoin(origin,urljoin(str(root),name))

                if urlparse(u).scheme in ('http','https') and in_scope(u,cfg):
                    urls.append(canon(u))

    return out,urls

def links(doc,cfg):
    out=[]

    for rx in (SCRIPT,JSLINK):
        for m in rx.finditer(doc.text):
            u=canon(urljoin(doc.url,m[1]))

            if urlparse(u).scheme in ('http','https') and in_scope(u,cfg):
                out.append(u)

    return out

def analyze_doc(doc,cfg,depth):
    out=scan(doc.text,doc.url,cfg)
    more=[]
    obj=text_json(doc.text)

    if obj and (
        isinstance(obj.get('sources'),list)
        or isinstance(obj.get('sections'),list)
    ):
        a,b=map_content(obj,doc.url,cfg)
        out+=a
        more+=b

    if cfg.follow:
        for m in MAPREF.finditer(doc.text):
            ref=m[1].strip().strip('"\'')

            if ref.startswith('data:'):
                z=data_map(ref)

                if z:
                    a,b=map_content(z,doc.url,cfg)
                    out+=a
                    more+=b
            else:
                u=canon(urljoin(doc.url,ref))

                if urlparse(u).scheme in ('http','https') and in_scope(u,cfg):
                    more.append(u)

        if depth<cfg.max_depth:
            more+=links(doc,cfg)

    return out,more

def crawl(seeds,cfg):
    q=deque((canon(u),0) for u in seeds if in_scope(u,cfg))
    seen=set()
    allf=[]

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1,cfg.threads)
    ) as ex:

        while q and (not cfg.max_urls or len(seen)<cfg.max_urls):
            batch=[]

            while (
                q
                and len(batch)<max(1,cfg.threads)
                and (not cfg.max_urls or len(seen)+len(batch)<cfg.max_urls)
            ):
                u,d=q.popleft()

                if u in seen or d>cfg.max_depth:
                    continue

                seen.add(u)
                batch.append((u,d))

            if not batch:
                continue

            jobs={ex.submit(fetch,u,cfg):(u,d) for u,d in batch}

            for job in concurrent.futures.as_completed(jobs):
                u,d=jobs[job]

                try:
                    doc=job.result()
                except Exception as e:
                    log(f'[SKIP] {clean_url(u)}: {e}')
                    continue

                if not doc:
                    continue

                f,nxt=analyze_doc(doc,cfg,d)
                allf+=f

                if cfg.follow and d<cfg.max_depth:
                    for v in nxt:
                        if v not in seen:
                            q.append((v,d+1))

    return allf

def contained(root,p):
    try:return os.path.commonpath((str(root),str(p)))==str(root)
    except ValueError:return False

def local_map_obj(obj,map_path,root,cfg,tag='source'):
    out=[]

    for part in map_parts(obj):
        src=part.get('sources')
        body=part.get('sourcesContent')
        sr=part.get('sourceRoot','')

        if not isinstance(src,list):
            continue

        body=body if isinstance(body,list) else []

        for i,name in enumerate(src):
            content=body[i] if i<len(body) else None

            if isinstance(content,str):
                out+=scan(
                    content,
                    str(map_path)+f'#source-{i+1}',
                    cfg,
                    tag
                )

            elif isinstance(name,str):
                q=urlparse(name)

                if q.scheme or q.netloc:
                    continue

                p=(map_path.parent/str(sr)/unquote(q.path)).resolve()

                if not contained(root,p) or not p.is_file():
                    continue

                try:
                    if cfg.max_bytes and p.stat().st_size>cfg.max_bytes:
                        continue

                    out+=scan(
                        p.read_text(encoding='utf-8',errors='replace'),
                        str(p),
                        cfg,
                        'source'
                    )
                except OSError:
                    pass

    return out

def local_maps(text,source,cfg,root=None):
    out=[]

    if source=='stdin':
        for m in MAPREF.finditer(text):
            z=data_map(m[1].strip().strip('"\''))

            if z:
                out+=local_map_obj(
                    z,
                    Path('stdin.map'),
                    Path.cwd().resolve(),
                    cfg,
                    'inline_map'
                )

        return out

    path=Path(source).resolve()
    root=(root or path.parent).resolve()
    obj=text_json(text)

    if obj and (
        isinstance(obj.get('sources'),list)
        or isinstance(obj.get('sections'),list)
    ):
        out+=local_map_obj(obj,path,root,cfg)

    for m in MAPREF.finditer(text):
        ref=m[1].strip().strip('"\'')
        z=data_map(ref)

        if z:
            out+=local_map_obj(z,path,root,cfg,'inline_map')
            continue

        q=urlparse(ref)

        if q.scheme or q.netloc:
            continue

        mp=(path.parent/unquote(q.path)).resolve()

        if not contained(root,mp) or not mp.is_file():
            continue

        try:
            if cfg.max_bytes and mp.stat().st_size>cfg.max_bytes:
                continue

            z=text_json(mp.read_text(
                encoding='utf-8',
                errors='replace'
            ))

            if z:
                out+=local_map_obj(z,mp,root,cfg)

        except OSError:
            pass

    return out

def local_targets(targets,cfg):
    out=[]
    ext={
        '.js','.mjs','.cjs','.json','.map','.html','.htm',
        '.txt','.jsx','.ts','.tsx'
    }

    for name in targets:
        if name=='-':
            text=sys.stdin.read()
            out+=scan(text,'stdin',cfg)
            out+=local_maps(text,'stdin',cfg)
            continue

        p=Path(name).expanduser().resolve()
        root=p if p.is_dir() else p.parent

        files=(
            [p]
            if p.is_file()
            else (
                [
                    x.resolve()
                    for x in p.rglob('*')
                    if x.is_file()
                    and x.suffix.lower() in ext
                    and contained(root,x.resolve())
                ]
                if p.is_dir()
                else []
            )
        )

        if not files:
            log(f'[SKIP] {name}: not a readable file or directory')
            continue

        for x in files:
            try:
                if cfg.max_bytes and x.stat().st_size>cfg.max_bytes:
                    raise ValueError('file exceeds limit')

                text=x.read_text(
                    encoding='utf-8',
                    errors='replace'
                )
                src=str(x)

                out+=scan(text,src,cfg)
                out+=local_maps(text,src,cfg,root)

            except (OSError,ValueError) as e:
                log(f'[SKIP] {x}: {e}')

    return out

def unique(items):
    best={}

    for f in items:
        k=(f.source,f.provider,f.token)

        if k not in best or CONF[f.confidence]<CONF[best[k].confidence]:
            best[k]=f

    return sorted(
        best.values(),
        key=lambda f:(
            ORDER[f.severity],
            f.source,
            f.line or 0,
            f.provider
        )
    )

def secure_open(path):
    fd=os.open(
        path,
        os.O_WRONLY|os.O_CREAT|os.O_TRUNC,
        0o600
    )

    try:os.chmod(path,0o600)
    except OSError:pass

    return os.fdopen(
        fd,
        'w',
        encoding='utf-8',
        newline=''
    )

def reports(
    items,
    json_path=None,
    jsonl_path=None,
    csv_path=None,
    full=False
):
    rows=[x.record(full) for x in items]

    if json_path:
        with secure_open(json_path) as f:
            json.dump(
                rows,
                f,
                indent=2,
                ensure_ascii=False
            )
            f.write('\n')

    if jsonl_path:
        with secure_open(jsonl_path) as f:
            for x in rows:
                f.write(json.dumps(
                    x,
                    ensure_ascii=False
                )+'\n')

    if csv_path:
        fields=[
            'finding_id','severity','confidence','provider',
            'category','source','line','column','transform',
            'redacted','context'
        ]+(['token'] if full else [])

        with secure_open(csv_path) as f:
            w=csv.DictWriter(
                f,
                fieldnames=fields,
                extrasaction='ignore'
            )
            w.writeheader()
            w.writerows(rows)

def args(argv=None):
    p=argparse.ArgumentParser(
        description=(
            'Precision-first hardcoded credential scanner '
            'for authorized JavaScript assessment.'
        )
    )

    p.add_argument(
        'targets',
        nargs='+',
        help='Authorized http(s) URL, local file/directory, or - for stdin'
    )

    p.add_argument(
        '--scope',
        action='append',
        default=[],
        help=(
            'Authorized exact hostname; use *.example.com only '
            'when all subdomains are authorized'
        )
    )

    p.add_argument(
        '--threads',
        type=int,
        default=THREADS
    )

    p.add_argument(
        '--timeout',
        type=int,
        default=TIMEOUT
    )

    p.add_argument(
        '--max-bytes',
        type=int,
        default=MAX_BYTES
    )

    p.add_argument(
        '--max-urls',
        type=int,
        default=MAX_URLS,
        help='0 means unlimited'
    )

    p.add_argument(
        '--max-depth',
        type=int,
        default=MAX_DEPTH
    )

    p.add_argument(
        '--no-follow',
        action='store_true'
    )

    p.add_argument(
        '--no-decode',
        action='store_true'
    )

    p.add_argument(
        '--generic',
        action='store_true',
        help=(
            'Opt in to heuristic generic-secret matching '
            '(off by default)'
        )
    )

    p.add_argument('--json-report')
    p.add_argument('--jsonl-report')
    p.add_argument('--csv-report')

    p.add_argument(
        '--show-secrets-in-report',
        action='store_true',
        help=(
            'Include full values only in mode-0600 report files; '
            'console stays redacted'
        )
    )

    p.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Write diagnostics to stderr'
    )

    return p.parse_args(argv)

def main(argv=None):
    global VERBOSE,MIN_ENTROPY

    a=args(argv)
    VERBOSE=a.verbose

    if (
        a.threads<1
        or a.timeout<1
        or a.max_bytes<1
        or a.max_urls<0
        or a.max_depth<0
    ):
        raise SystemExit('numeric limits are invalid')

    remote=[
        x
        for x in a.targets
        if urlparse(x).scheme in ('http','https')
    ]

    local=[
        x
        for x in a.targets
        if x not in remote
    ]

    scope=a.scope or sorted({
        urlparse(x).hostname or ''
        for x in remote
    })

    cfg=Config(
        scope,
        max(1,a.threads),
        a.timeout,
        a.max_bytes,
        a.max_urls,
        a.max_depth,
        MIN_ENTROPY,
        not a.no_follow,
        not a.no_decode,
        a.generic
    )

    found=local_targets(local,cfg)+crawl(remote,cfg)
    found=unique(found)

    for f in found:
        loc=f.source+(
            f':{f.line}:{f.column}'
            if f.line
            else ''
        )

        print(
            f'[FOUND {f.severity.upper():8}] '
            f'{f.provider:30} '
            f'{f.redacted:32} '
            f'{loc}'
        )

    reports(
        found,
        a.json_report,
        a.jsonl_report,
        a.csv_report,
        a.show_secrets_in_report
    )

    return 1 if found else 0

if __name__=='__main__':
    raise SystemExit(main())
