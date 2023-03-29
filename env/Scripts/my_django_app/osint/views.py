from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

import requests
import dns.resolver
from geopy.geocoders import Nominatim
import whois
import uuid

@csrf_exempt
def generate_report(request):
    if request.method == 'POST':
        url = request.POST.get('url')

        # VirusTotal report
        vt_report = get_vt_report(url, '7dd683a5fd7df638c8efbaae2979bb7aca843530956ceeeaa9ff51d7dfe34af5')

        # DNS report
        dns_report = get_dns_report(url)

        # GeoPy report
        geopy_report = get_geopy_report(url)

        # WHOIS report
        whois_report = get_whois_report(url)

        # UUID analysis
        uuid_analysis = analyze_uuid(str(uuid.uuid4()))

        context = {
            'url': url,
            'vt_report': vt_report,
            'dns_report': dns_report,
            'geopy_report': geopy_report,
            'whois_report': whois_report,
            'uuid_analysis': uuid_analysis
        }
        return render(request, "index.html",context)
    else:
        return render(request, 'index.html')


def get_vt_report(url, api_key):
    params = {'apikey': api_key, 'resource': url}
    headers = {'Accept-Encoding': 'gzip, deflate', 'User-Agent' : 'gzip'}
    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    json_response = response.json()
    return json_response


def get_dns_report(url):
    answers = dns.resolver.query(url)
    result = []
    for rdata in answers:
        result.append(str(rdata))
    return result


def get_geopy_report(url):
    geolocator = Nominatim(user_agent="geoapiExercises")
    location = geolocator.geocode(url)
    if location:
        return {
            'address': location.address,
            'latitude': location.latitude,
            'longitude': location.longitude
        }
    else:
        return None


def get_whois_report(url):
    w = whois.whois(url)
    return w


def analyze_uuid(uuid_str):
    uuid_obj = uuid.UUID(uuid_str)
    return {
        'hex': uuid_obj.hex,
        'int': uuid_obj.int,
        'urn': uuid_obj.urn,
        'variant': uuid_obj.variant,
        'version': uuid_obj.version,
    }
