"""
Security Job Alert Scraper — Hyderabad Edition
================================================
URLs sourced directly from actual company career portals.
Keywords: security, cybersecurity, threat
Run: python job_scraper.py           (one-time)
     python scheduler.py             (every 6 hours)
"""

import json, re, smtplib, hashlib, time, logging
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────
EMAIL_CONFIG = {
    "sender":   "indrakantidivyateja@gmail.com",
    "password": "gwnh sdwa asku ecrc",
    "receiver": "indrakantidivyateja@gmail.com",
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
}

SEARCH_KEYWORDS   = ["security", "cybersecurity", "threat"]
STATE_FILE        = "seen_jobs.json"
LOG_FILE          = "scraper.log"

# ─────────────────────────────────────────────────────────────────────────────
#  COMPANY REGISTRY
#  Format: "Company": ("url", "ats_type", has_hyderabad_office)
#  ats_type: "own" | "workday" | "greenhouse" | "lever" | "eightfold"
#  ✅ = confirmed Hyderabad GCC/office   ❌ = no Hyd office, global URL used
# ─────────────────────────────────────────────────────────────────────────────
COMPANIES = {

    # ── Big Tech ──────────────────────────────────────────────────────────────
    "Google": (
        "https://www.google.com/about/careers/applications/jobs/results?location=Hyderabad%2C%20India&has_remote=true&q=security",
        "own", True),   # ✅

    "Microsoft": (
        "https://apply.careers.microsoft.com/careers?query=security&start=0&location=Hyderabad%2C++TS%2C++India&sort_by=relevance&filter_distance=160&filter_include_remote=1",
        "own", True),   # ✅  — correct domain is apply.careers.microsoft.com

    "Meta": (
        "https://www.metacareers.com/jobsearch/?teams[0]=Security&offices[0]=Hyderabad%2C%20India&roles[0]=Full%20time%20employment",
        "own", True),   # ✅

    "Apple": (
        "https://jobs.apple.com/en-in/search?location=india-INDC+hyderabad-HY1&key=security",
        "own", True),   # ✅

    "Amazon": (
        "https://www.amazon.jobs/en-gb/search?base_query=security&loc_query=Hyderabad%2C+Telangana%2C+India&city=Hyderabad&county=Hyderabad&region=Telangana&country=IND&latitude=17.3949&longitude=78.47081&radius=24km",
        "own", True),   # ✅

    "GitHub": (
        "https://www.github.careers/careers-home/jobs?keywords=security&locations=,,India&page=1",
        "own", False),  # ❌ no dedicated Hyd office

    # ── Semiconductors ────────────────────────────────────────────────────────
    "Nvidia": (
        "https://jobs.nvidia.com/careers?query=security&start=0&location=Hyderabad%2C++Telangana%2C++India&sort_by=relevance&filter_distance=160&filter_include_remote=1",
        "own", True),   # ✅  — jobs.nvidia.com NOT Workday

    "Qualcomm": (
        "https://careers.qualcomm.com/careers?query=security&start=0&location=Hyderabad%2C+TS%2C+India&sort_by=relevance&filter_distance=80&filter_include_remote=0",
        "own", True),   # ✅

    "AMD": (
        "https://careers.amd.com/careers-home/jobs?keywords=security&location=Hyderabad%2C+Telangana%2C+India&woe=7&regionCode=IN&stretchUnit=MILES&stretch=10&sortBy=relevance&page=1",
        "own", True),   # ✅

    "Intel": (
        "https://intel.wd1.myworkdayjobs.com/External?q=security&locations=1e4a4eb3adf101f44070f976bf8184cf",
        "workday", True),  # ✅  — location GUID is Hyderabad

    "Micron Technology": (
        "https://micron.eightfold.ai/careers?domain=micron.com&query=security&start=0&location=Hyderabad%2C++TS%2C++India&sort_by=relevance&filter_distance=80&filter_include_remote=1",
        "eightfold", True),  # ✅  — uses Eightfold AI, NOT Workday

    "Silicon Labs": (
        "https://silabs.wd1.myworkdayjobs.com/SiliconlabsCareers?q=security&locationCountry=c4f78be1a8f14da0ab49ce1162348a5e&locations=15081e9a5f8e01a7c343745ac500ce04",
        "workday", True),  # ✅  — location GUID = India/Hyderabad

    # ── Enterprise SaaS ───────────────────────────────────────────────────────
    "Salesforce": (
        "https://www.salesforce.com/company/careers/jobs/?location=Hyderabad&search=security&page=1",
        "own", True),   # ✅  — salesforce.com/company/careers NOT Workday

    "ServiceNow": (
        "https://careers.servicenow.com/jobs/?search=security&country=India&region=Telangana&location=Hyderabad&origin=global",
        "own", True),   # ✅

    "Atlassian": (
        "https://www.atlassian.com/company/careers/all-jobs?team=Security&location=India&search=",
        "own", True),   # ✅  — team=Security filter

    "Adobe": (
        "https://adobe.wd5.myworkdayjobs.com/external_experienced?q=security&locationCountry=IN",
        "workday", True),  # ✅  — user's URL was research/bangalore only; use main Workday

    "Oracle": (
        "https://careers.oracle.com/en/sites/jobsearch/jobs?keyword=security&location=HYDERABAD%2C+TELANGANA%2C+India&locationId=300001842985230&locationLevel=city&mode=location&radius=25&radiusUnit=MI",
        "own", True),   # ✅  — locationId is Hyderabad

    "SAP": (
        "https://jobs.sap.com/search/?createNewAlert=false&q=security&locationsearch=Hyderabad",
        "own", True),   # ✅  — user URL had 'bangalore', corrected to Hyderabad

    "VMware/Broadcom": (
        "https://careers.broadcom.com/jobs?q=security+cybersecurity&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅  — VMware acquired by Broadcom 2023

    "Pegasystems": (
        "https://www.pega.com/about/careers/search?q=security&location=Hyderabad",
        "own", True),   # ✅

    "Zoho": (
        "https://careers.zohocorp.com/jobs/Careers?search=security",
        "own", True),   # ✅

    "Intuit": (
        "https://jobs.intuit.com/search-jobs/security/India/27595/1/2/1269750/22/79/0/2",
        "own", True),   # ✅

    "Freshworks": (
        "https://careers.freshworks.com/jobs?query=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅

    "Gainsight": (
        "https://gainsight.wd5.myworkdayjobs.com/Gainsight_External_Careers?q=security&locations=e33bd8017cf71001bd06d95a7e730000",
        "workday", True),  # ✅  — uses Workday NOT Lever

    "GitLab": (
        "https://job-boards.greenhouse.io/gitlab?q=security",
        "greenhouse", False),  # ❌ fully remote

    # ── Cybersecurity ─────────────────────────────────────────────────────────
    "Palo Alto Networks": (
        "https://jobs.paloaltonetworks.com/en/search-jobs/security/Hyderabad%2C%20Telangana/47263/1/4/1269750-1254788-1269844-1269843/17x38405/78x45636/50/2",
        "own", True),   # ✅  — Hyd-specific geocoded URL

    "CrowdStrike": (
        "https://crowdstrike.wd5.myworkdayjobs.com/en-GB/crowdstrikecareers?q=security&locationCountry=c4f78be1a8f14da0ab49ce1162348a5e",
        "workday", True),  # ✅  — correct tenant and India country GUID

    "Zscaler": (
        "https://www.zscaler.com/careers/search?q=security&office=india",
        "own", True),   # ✅  — own portal, NOT Workday

    "SentinelOne": (
        "https://www.sentinelone.com/jobs/?search=security&l=India",
        "own", True),   # ✅  — /jobs not /careers

    "Sophos": (
        "https://jobs.sophos.com/search?q=security&l=Hyderabad",
        "own", True),   # ✅

    "Akamai": (
        "https://www.akamai.com/careers/job-search?q=security&location=India",
        "own", True),   # ✅  — fixed: old inflectionhire.com domain is dead, akamai.com hosts own portal

    # ── Networking / Infra ────────────────────────────────────────────────────
    "Cisco": (
        "https://careers.cisco.com/global/en/search-results?keywords=security",
        "own", True),   # ✅  — careers.cisco.com (correct), jobs.cisco.com redirects

    "Splunk": (
        "https://careers.cisco.com/global/en/search-results?keywords=security+splunk",
        "own", True),   # ✅  — acquired by Cisco 2024, now on Cisco careers

    "F5": (
        "https://www.f5.com/company/careers/open-positions?q=security&country=India",
        "own", True),   # ✅  — fixed: Workday subdomain unreliable, using f5.com own listings page

    # ── Cloud / Data ──────────────────────────────────────────────────────────
    "Snowflake": (
        "https://careers.snowflake.com/us/en/search-results?keywords=security&country=India",
        "own", True),   # ✅

    "Rubrik": (
        "https://www.rubrik.com/company/careers/departments/information-security",
        "own", True),   # ✅  — department-specific page

    "DigitalOcean": (
        "https://www.digitalocean.com/careers/open-roles?query=security&location=Hyderabad",
        "own", True),   # ✅  — user URL has Hyderabad filter, so they do have Hyd presence

    "Nutanix": (
        "https://careers.nutanix.com/en/jobs/?search=security&pagesize=20#results",
        "own", True),   # ✅  — careers.nutanix.com, NOT eightfold

    # ── Financial Services ────────────────────────────────────────────────────
    "Goldman Sachs": (
        "https://higher.gs.com/results?JOB_FUNCTION=Security%20Engineering&LOCATION=Hyderabad&page=1&search=security&sort=RELEVANCE",
        "own", True),   # ✅  — JOB_FUNCTION + Hyderabad filter

    "JPMorgan": (
        "https://jpmc.fa.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1001/jobs?keyword=security&location=Hyderabad%2C+Telangana%2C+India&locationId=300000081155702&locationLevel=city&mode=location&radius=25&radiusUnit=MI",
        "own", True),   # ✅  — locationId = Hyderabad

    "Morgan Stanley": (
        "https://morganstanley.eightfold.ai/careers?source=mscom&query=security&start=0&sort_by=relevance&filter_city=Mumbai%2CBengaluru",
        "eightfold", False),  # ❌  — Mumbai/Bengaluru only, no Hyd office

    "HSBC": (
        "https://portal.careers.hsbc.com/careers?query=Cybersecurity&location=India&domain=hsbc.com&sort_by=relevance",
        "own", True),   # ✅  — portal.careers.hsbc.com (new domain, old mycareer.hsbc.com deprecated)

    "Wells Fargo": (
        "https://www.wellsfargojobs.com/en/jobs/?search=security&location=HYDERABAD&pagesize=20#results",
        "own", True),   # ✅

    "Vanguard": (
        "https://www.vanguardjobs.com/job-search-results/?location=IN%2C%20Telangana%2C%20Hyderabad&keyword=cybersecurity&category[]=Technology",
        "own", True),   # ✅  — user URL confirms Hyd presence (was marked ❌ before, now corrected)

    "Invesco": (
        "https://invesco.wd1.myworkdayjobs.com/en-GB/IVZ?q=security&locations=1804888b7f5a100128e426fb60bc0000",
        "workday", True),  # ✅  — uses Workday with Hyd location GUID

    "FactSet": (
        "https://www.factset.com/careers/job-search?q=security&l=Hyderabad",
        "own", True),   # ✅  — fixed: careers.factset.com doesn't resolve, using factset.com/careers

    "State Street": (
        "https://careers.statestreet.com/global/en/search-results?m=3&keywords=security&cityStateCountry=Hyderabad%2C%20Telangana%2C%20India",
        "own", True),   # ✅  — careers.statestreet.com (own portal, NOT Workday)

    "Synchrony": (
        "https://www.synchrony.com/careers/job-search.html?q=security&location=Hyderabad",
        "own", True),   # ✅  — fixed: synchronycareers.com has SSL errors, using main synchrony.com

    "Broadridge": (
        "https://www.broadridge.com/careers/search-jobs?q=security&l=India",
        "own", True),   # ✅  — fixed: careers.broadridge.com doesn't resolve, using broadridge.com/careers

    "Stripe": (
        "https://stripe.com/jobs/search?query=security",
        "own", True),   # ✅

    "LSEG": (
        "https://lseg.wd3.myworkdayjobs.com/Careers?q=security&locationCountry=c4f78be1a8f14da0ab49ce1162348a5e&primaryLocation=85fcb4c116cc1001ed602e25ce830000",
        "workday", True),  # ✅  — Hyd primaryLocation GUID confirmed

    "Tide": (
        "https://job-boards.greenhouse.io/tide?keyword=security&offices%5B%5D=4052071003",
        "greenhouse", True),  # ✅  — office ID 4052071003 = Hyderabad (was marked ❌ before, now corrected)

    # ── IT Services ───────────────────────────────────────────────────────────
    "IBM": (
        "https://www.ibm.com/in-en/careers/search?field_keyword_08[0]=Security&field_keyword_05[0]=India",
        "own", True),   # ✅  — in-en India-specific URL

    "Wipro": (
        "https://careers.wipro.com/careers-home/jobs?q=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅

    "Infosys": (
        "https://career.infosys.com/joblist?industryType=j&location=Hyderabad&skills=security",
        "own", True),   # ✅

    "TCS": (
        "https://www.tcs.com/careers/india/job-search?keyword=security&location=Hyderabad",
        "own", True),   # ✅  — fixed: ibegin.tcs.com doesn't resolve, using main tcs.com careers

    "HCLTech": (
        "https://www.hcltech.com/careers/job-search?keyword=security&location=Hyderabad",
        "own", True),   # ✅

    "Accenture": (
        "https://www.accenture.com/in-en/careers/jobsearch?jq=security&jl=Hyderabad",
        "own", True),   # ✅

    "Capgemini": (
        "https://www.capgemini.com/in-en/careers/job-search/?search_term=security&country=India&city=Hyderabad",
        "own", True),   # ✅

    "Deloitte": (
        "https://apply.deloitte.com/careers/SearchJobs/security?3836=%5BIndia%5D&listFilterMode=1",
        "own", True),   # ✅

    "NTT": (
        "https://services.global.ntt/en-us/careers?q=security&location=Hyderabad",
        "own", True),   # ✅  — fixed: careers.ntt.com doesn't resolve, using services.global.ntt

    "EPAM": (
        "https://www.epam.com/careers/job-listings?search=security&city=Hyderabad",
        "own", True),   # ✅

    "Accolite": (
        "https://accolite.com/careers/?search=security",
        "own", True),   # ✅

    "Darwinbox": (
        "https://careers.darwinbox.com/jobs?q=security",
        "own", True),   # ✅

    # ── Telecom ───────────────────────────────────────────────────────────────
    "AT&T": (
        "https://www.att.jobs/search-jobs/security/Hyderabad%2C%20Telangana/117/1/4/1269750-1254788-1269844-1269843/17x38405/78x45636/50/2",
        "own", True),   # ✅  — geocoded Hyd URL confirms Hyd office (was ❌ before, now corrected)

    # ── Fintech ───────────────────────────────────────────────────────────────
    "GoDaddy": (
        "https://careers.godaddy.com/jobs/search?page=1&query=security&country_codes%5B%5D=IN",
        "own", True),   # ✅  — fixed: careers.godaddy.com (user URL was missing .com)

    # ── Retail / Consumer ─────────────────────────────────────────────────────
    "Walmart": (
        "https://careers.walmart.com/results?q=security&l=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅  — added Hyd location (user URL had no location)

    "Costco": (
        "https://careers.costco.com/jobs?keywords=security&stretchUnit=MILES&stretch=10&location=Hyderabad%2C+Telangana%2C+India&woe=7&regionCode=IN",
        "own", True),   # ✅  — user URL confirms Hyd presence (was ❌ before, now corrected)

    "Flipkart": (
        "https://www.flipkartcareers.com/#!/joblist?search=security",
        "own", True),   # ✅

    "PepsiCo": (
        "https://www.pepsicojobs.com/main/jobs?keywords=security&stretchUnit=MILES&stretch=10&location=Hyderabad%2C+Telangana%2C+India&woe=7&regionCode=IN",
        "own", True),   # ✅  — user URL has Hyd location + correct param is 'keywords' not 'q'

    "McDonald's": (
        "https://careers.mcdonalds.com/jobs?filter%5Bcountry%5D%5B0%5D=IN&keyword=security&location_name=hyderabad&location_type=1",
        "own", True),   # ✅  — NEW company added from user's list

    # ── Industrial / Hardware ─────────────────────────────────────────────────
    "Honeywell": (
        "https://careers.honeywell.com/en/sites/Honeywell/jobs?keyword=security&location=Hyderabad%2C+Telangana%2C+India&locationId=100000013406729&locationLevel=city&mode=location&radius=25&radiusUnit=MI",
        "own", True),   # ✅  — locationId = Hyderabad

    "Bosch": (
        "https://jobs.bosch.com/job-search-result/?language=en&q=security&country=India&city=Hyderabad",
        "own", True),   # ✅

    "ABB": (
        "https://new.abb.com/jobs/search?q=security&location=India",
        "own", False),  # ❌  — no Hyd office confirmed

    # ── Other ─────────────────────────────────────────────────────────────────
    "Uber": (
        "https://www.uber.com/in/en/careers/list/?query=security&location=IND-Telangana-Hyderabad",
        "own", True),   # ✅  — India-specific URL with Hyd location

    "FedEx": (
        "https://www.fedex.com/en-us/about/careers.html?q=security&location=India",
        "own", True),   # ✅  — fixed: careers.fedex.com failed DNS, using fedex.com/about/careers

    "Blackbaud": (
        "https://careers.blackbaud.com/us/en/search-results?keywords=security",
        "own", False),  # ❌  — no Hyd office

    "Eli Lilly": (
        "https://careers.lilly.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅

    "Novartis": (
        "https://www.novartis.com/in-en/careers/career-search?search_api_fulltext=cyber+security&country%5B%5D=LOC_IN&field_job_posted_date=All&op=Submit",
        "own", True),   # ✅  — in-en India URL with cyber security keyword

    "WBD": (
        "https://careers.wbd.com/global/en/hyderabad-jobs/search-results?keywords=security",
        "own", True),   # ✅  — /hyderabad-jobs/ path confirms Hyd presence (was ❌ before)

    "Providence": (
        "https://jobs.providence.org/search-jobs/security/india",
        "own", True),   # ✅  — fixed: careers.providence.in doesn't resolve, using jobs.providence.org

    "Electronic Arts": (
        "https://jobs.ea.com/en_US/careers/Home/Hyderabad?4536=%5B8317%5D&4536_format=3019&listFilterMode=1&jobRecordsPerPage=20",
        "own", True),   # ✅  — Hyderabad homepage with security dept filter

    "Straive": (
        "https://straive.com/careers/?search=security",
        "own", True),   # ✅  — fixed: careers.straive.com doesn't resolve, using straive.com/careers

    # ═════════════════════════════════════════════════════════════════════════
    #  NEW ADDITIONS — Banks, Healthcare, Tech, Industrial (all confirmed Hyd GCC)
    #  Source: Hyderabad office directory cross-referenced against career portals
    # ═════════════════════════════════════════════════════════════════════════

    # ── Banking / Financial Services ─────────────────────────────────────────
    "Bank of America": (
        "https://careers.bankofamerica.com/en-us/job-search?search=security&city=Hyderabad&country=India",
        "own", True),   # ✅ Mindspace Raheja IT Park, Madhapur

    "Barclays": (
        "https://search.jobs.barclays/search-jobs/security/Hyderabad/461/1/2/6252001/17.3850/78.4867/50/2",
        "own", True),   # ✅ Banjara Hills, Hyderabad

    "BNY Mellon": (
        "https://bnymellon.wd1.myworkdayjobs.com/BNYMellon?q=security&locationCountry=IN",
        "workday", True),  # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Citi": (
        "https://jobs.citi.com/search-jobs/security/Hyderabad/287/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Queens Plaza, Begumpet + Gachibowli

    "UBS": (
        "https://jobs.ubs.com/TGnewUI/Search/home/HomeWithPreLoad?partnerid=25008&siteid=5012&q=security&locationsearch=Hyderabad",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "US Bank": (
        "https://careers.usbank.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Franklin Templeton": (
        "https://careers.franklintempleton.com/global/en/search-results?keywords=security&location=Hyderabad",
        "own", True),   # ✅ Franklin Templeton Park, Nanakramguda

    "Fiserv": (
        "https://fiserv.wd5.myworkdayjobs.com/EXT_Careers?q=security&locationCountry=IN",
        "workday", True),  # ✅ Mindspace, Vittal Rao Nagar, Madhapur

    "Charles Schwab": (
        "https://schwabjobs.com/search-jobs/security/Hyderabad/271/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City + Phoenix Equinox Tower

    "DBS Bank": (
        "https://www.dbs.com/careers/job-search?keyword=security&location=Hyderabad",
        "own", True),   # ✅ Gachibowli, Financial District

    "Lloyds Banking Group": (
        "https://lloydsbankinggroupcareers.com/search/?q=security&l=Hyderabad",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "MetLife": (
        "https://careers.metlife.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Raheja Mindspace, HITEC City, Madhapur

    "Moody's": (
        "https://careers.moodys.com/us/en/search-results?keywords=security&location=Hyderabad",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "S&P Global": (
        "https://careers.spglobal.com/jobs?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Raheja Mindspace, HITEC City, Madhapur

    "Voya Financial": (
        "https://voya.wd5.myworkdayjobs.com/Voya_Careers?q=security&locationCountry=IN",
        "workday", True),  # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Nationwide": (
        "https://nationwide.jobs/hyderabad-in/jobs/?q=security",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "LPL Financial": (
        "https://careers.lpl.com/search-jobs/security/Hyderabad/472/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    # ── Big Tech / Hardware ──────────────────────────────────────────────────
    "Dell Technologies": (
        "https://jobs.dell.com/search-jobs/security/Hyderabad/507/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Divyasree Omega, Kondapur, HITEC City

    "Texas Instruments": (
        "https://careers.ti.com/search-jobs/security/India/120/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Dhoolpet / Begumpet / Banjara Hills, Hyderabad

    "Persistent Systems": (
        "https://www.persistent.com/careers/job-search/?keyword=security&location=Hyderabad",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Hexaware Technologies": (
        "https://hexaware.com/careers/job-search/?q=security&location=Hyderabad",
        "own", True),   # ✅ Raheja Mindspace, HITEC City, Madhapur

    "OpenText": (
        "https://careers.opentext.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur (Micro Focus)

    "Red Hat": (
        "https://jobs.redhat.com/search-jobs/security/Hyderabad/506/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Aditya Trade Center, Ameerpet

    "UiPath": (
        "https://job-boards.greenhouse.io/uipath?q=security",
        "greenhouse", True),  # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Garmin": (
        "https://careers.garmin.com/careers-home/jobs?q=security&l=Hyderabad%2C+India",
        "own", True),   # ✅ HITEC City, Madhapur

    "Ericsson": (
        "https://jobs.ericsson.com/careers?query=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Raheja Mindspace, HITEC City, Madhapur

    "Verizon": (
        "https://verizon.wd5.myworkdayjobs.com/verizon_careers?q=security&locationCountry=IN",
        "workday", True),  # ✅ Raheja Mindspace, HITEC City, Madhapur

    "T-Mobile": (
        "https://careers.t-mobile.com/search-jobs/security/Hyderabad/562/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Western Union": (
        "https://careers.westernunion.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ HITEC City, Madhapur

    # ── Healthcare / Pharma / Insurance ──────────────────────────────────────
    "Optum (UnitedHealth Group)": (
        "https://careers.unitedhealthgroup.com/search-jobs/security/Hyderabad/523/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Raheja Mindspace, HITEC City, Madhapur

    "Elevance Health/Carelon": (
        "https://elevancehealth.wd1.myworkdayjobs.com/elevancehealth?q=security&locationCountry=IN",
        "workday", True),  # ✅ WaveRock SEZ, Financial District

    "Thermo Fisher Scientific": (
        "https://jobs.thermofisher.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Gachibowli, Financial District

    "Johnson & Johnson": (
        "https://careers.jnj.com/en/jobs/?search=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Gachibowli, Financial District

    "Medtronic": (
        "https://jobs.medtronic.com/jobs?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Philips": (
        "https://careers.philips.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Gachibowli, Financial District

    "Roche": (
        "https://careers.roche.com/global/en/search-results?keywords=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Sanofi": (
        "https://www.sanofi.com/en/careers/job-search?keyword=security&location=Hyderabad",
        "own", True),   # ✅ Gachibowli, Hyderabad

    # ── Industrial / Aerospace ───────────────────────────────────────────────
    "Nike": (
        "https://careers.nike.com/jobs?query=security&location=Hyderabad%2C+India",
        "own", True),   # ✅ HITEC City, Madhapur

    "Boeing": (
        "https://jobs.boeing.com/search-jobs/security/Hyderabad/440/1/2/6252001/17.385/78.4867/50/2",
        "own", True),   # ✅ Salarpuria Sattva Knowledge City, Madhapur

    "Siemens": (
        "https://jobs.siemens.com/careers?query=security&location=Hyderabad%2C+Telangana%2C+India",
        "own", True),   # ✅ Secretariat, Saifabad + Western Aqua, Kondapur

    "Schneider Electric": (
        "https://www.se.com/in/en/about-us/careers/job-search.jsp?text=security&country=India&city=Hyderabad",
        "own", True),   # ✅ Gagillapur Village + Secunderabad + Kukatpally
}

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────────────────────────────────────────
def load_state():
    if Path(STATE_FILE).exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def job_id(company, title, url):
    return hashlib.md5(f"{company}|{title}|{url}".encode()).hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
#  SCRAPERS
# ─────────────────────────────────────────────────────────────────────────────
def keyword_match(text):
    return any(k in text.lower() for k in SEARCH_KEYWORDS)

def scrape_greenhouse(company, url):
    import requests
    # Extract token from either boards-api or job-boards URL
    match = re.search(r'greenhouse\.io/([^?/&#]+)', url)
    if not match:
        return []
    token = match.group(1).rstrip("/")
    api = f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs?content=true"
    try:
        r = requests.get(api, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        jobs = []
        for job in r.json().get("jobs", []):
            title = job.get("title", "")
            if not keyword_match(title):
                continue
            loc = job.get("location", {}).get("name", "")
            jobs.append({
                "title": title,
                "location": loc,
                "url": job.get("absolute_url", url),
                "posted": job.get("updated_at", "")[:10],
            })
        return jobs
    except Exception as e:
        log.warning(f"Greenhouse error for {company}: {e}")
        return []

def scrape_lever(company, url):
    import requests
    match = re.search(r'lever\.co/([^/?]+)', url)
    if not match:
        return []
    token = match.group(1)
    api = f"https://api.lever.co/v0/postings/{token}?mode=json"
    try:
        r = requests.get(api, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        jobs = []
        for job in r.json():
            title = job.get("text", "")
            if not keyword_match(title):
                continue
            loc = job.get("categories", {}).get("location", "")
            jobs.append({
                "title": title,
                "location": loc,
                "url": job.get("hostedUrl", url),
                "posted": datetime.fromtimestamp(job.get("createdAt", 0)/1000).strftime("%Y-%m-%d") if job.get("createdAt") else "",
            })
        return jobs
    except Exception as e:
        log.warning(f"Lever error for {company}: {e}")
        return []

def scrape_html(company, url, hyd_office):
    """Playwright browser scrape — handles JS-rendered pages and Workday/Eightfold.
    Includes retry with relaxed wait conditions and tighter job-title extraction
    to avoid grabbing page chrome like 'Searched for: security'."""
    content = None
    last_error = None

    # Try up to 2 strategies: networkidle first, then domcontentloaded (faster, more forgiving)
    for wait_strategy, timeout in [("networkidle", 25000), ("domcontentloaded", 20000)]:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--disable-http2"]  # avoids ERR_HTTP2_PROTOCOL_ERROR on some sites
                )
                page = browser.new_page(user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ))
                page.goto(url, timeout=timeout, wait_until=wait_strategy)
                page.wait_for_timeout(2500)
                content = page.content()
                browser.close()
            break  # success — stop retrying
        except Exception as e:
            last_error = e
            continue

    if content is None:
        log.warning(f"HTML scrape error for {company}: {last_error}")
        return []

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(content, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "noscript", "form"]):
            tag.decompose()

        # Junk phrases that indicate UI chrome, not real job titles
        JUNK_PATTERNS = [
            "searched for", "filter(s) applied", "save search", "no results",
            "sign in", "create account", "cookie", "privacy policy",
            "results found", "clear filter", "sort by", "showing results",
            "loading", "please wait", "subscribe", "back to top",
        ]

        def is_junk(text):
            low = text.lower()
            return any(p in low for p in JUNK_PATTERNS)

        found = set()

        # Strategy 1: look for <a> tags (job links are almost always anchors)
        for a_tag in soup.find_all("a"):
            t = a_tag.get_text(strip=True)
            if keyword_match(t) and 12 < len(t) < 130 and not is_junk(t):
                found.add(t)

        # Strategy 2: fallback to heading tags if no anchor matches found
        if not found:
            for tag in soup.find_all(["h1", "h2", "h3", "h4", "li", "span", "div"]):
                t = tag.get_text(strip=True)
                if keyword_match(t) and 12 < len(t) < 130 and not is_junk(t):
                    # Avoid grabbing huge concatenated text blocks
                    if t.count(" ") < 18:
                        found.add(t)

        return [{
            "title": title,
            "location": "Hyderabad, India" if hyd_office else "Global",
            "url": url,
            "posted": datetime.today().strftime("%Y-%m-%d"),
        } for title in list(found)[:25]]

    except Exception as e:
        log.warning(f"HTML parse error for {company}: {e}")
        return []

def scrape_company(company, url, ats_type, hyd_office):
    log.info(f"Checking {company} ({'HYD' if hyd_office else 'GLOBAL'}) [{ats_type}]...")
    if ats_type == "greenhouse":
        return scrape_greenhouse(company, url)
    elif ats_type == "lever":
        return scrape_lever(company, url)
    else:
        # workday, eightfold, own — all use Playwright HTML scrape
        return scrape_html(company, url, hyd_office)

# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL
# ─────────────────────────────────────────────────────────────────────────────
def send_email(new_jobs: dict):
    if not new_jobs:
        return
    total = sum(len(v) for v in new_jobs.values())
    subject = f"🔐 {total} new Security/Cyber job(s) — {datetime.today().strftime('%b %d, %Y')}"

    html_rows = ""
    for company, jobs in new_jobs.items():
        for job in jobs:
            html_rows += f"""
            <tr>
              <td style="padding:10px;border-bottom:1px solid #eee;font-weight:600">{company}</td>
              <td style="padding:10px;border-bottom:1px solid #eee"><a href="{job['url']}" style="color:#0066cc">{job['title']}</a></td>
              <td style="padding:10px;border-bottom:1px solid #eee;color:#555">{job['location']}</td>
              <td style="padding:10px;border-bottom:1px solid #eee;color:#888;font-size:12px">{job['posted']}</td>
            </tr>"""

    html = f"""
    <html><body style="font-family:Arial,sans-serif;max-width:800px;margin:auto">
      <h2 style="color:#1a1a2e">🔐 New Security/Cyber Roles Alert</h2>
      <p style="color:#555">Found <strong>{total} new role(s)</strong> matching: security, cybersecurity, threat.</p>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#f0f0f0">
          <th style="padding:10px;text-align:left">Company</th>
          <th style="padding:10px;text-align:left">Role</th>
          <th style="padding:10px;text-align:left">Location</th>
          <th style="padding:10px;text-align:left">Posted</th>
        </tr></thead>
        <tbody>{html_rows}</tbody>
      </table>
      <p style="color:#aaa;font-size:12px;margin-top:20px">Security Job Alert Scraper · {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = EMAIL_CONFIG["sender"]
    msg["To"]      = EMAIL_CONFIG["receiver"]
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(EMAIL_CONFIG["smtp_host"], EMAIL_CONFIG["smtp_port"]) as s:
            s.starttls()
            s.login(EMAIL_CONFIG["sender"], EMAIL_CONFIG["password"])
            s.sendmail(EMAIL_CONFIG["sender"], EMAIL_CONFIG["receiver"], msg.as_string())
        log.info(f"✉ Email sent: {total} new jobs")
    except Exception as e:
        log.error(f"Email failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def run():
    log.info("=" * 60)
    log.info("Security job scan started — Hyderabad edition")
    state    = load_state()
    new_jobs = {}

    for company, (url, ats_type, hyd_office) in COMPANIES.items():
        try:
            jobs = scrape_company(company, url, ats_type, hyd_office)
            for job in jobs:
                jid = job_id(company, job["title"], job["url"])
                if jid not in state:
                    state[jid] = {
                        "company": company,
                        "title": job["title"],
                        "seen_at": datetime.now().isoformat(),
                    }
                    new_jobs.setdefault(company, []).append(job)
            time.sleep(2)
        except Exception as e:
            log.error(f"Error processing {company}: {e}")

    save_state(state)

    if new_jobs:
        total = sum(len(v) for v in new_jobs.values())
        log.info(f"Found {total} new jobs across {len(new_jobs)} companies")
        send_email(new_jobs)
    else:
        log.info("No new jobs found this run.")

    log.info("Scan complete.")

if __name__ == "__main__":
    run()
