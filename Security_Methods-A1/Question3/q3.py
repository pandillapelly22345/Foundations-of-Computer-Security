import csv
import socket
import asyncio
import aiohttp

class SubdomainFetcher:

    def __init__(self, domain, DUMPSTER_API, DUMPSTER_LINK, CRTSH_LINK):
        self.domain = domain
        self.subdomains = []
        self.DUMPSTER_API = DUMPSTER_API
        self.DUMPSTER_LINK = DUMPSTER_LINK
        self.CRTSH_LINK = CRTSH_LINK

    async def crtshFetching(self, session):
        async with session.get(self.CRTSH_LINK.format(self.domain)) as response:
            if response.status == 200:
                data = await response.json()
                a = [item['name_value'] for item in data]
                self.subdomains.extend(a)

    async def dnsdumpsterFetching(self, session):
        headers = {"Authorization": f"Bearer {self.DUMPSTER_API}"}
        async with session.get(self.DUMPSTER_LINK + self.domain, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                self.subdomains.extend(data.get('dns_records', {}).get('host', []))

    async def subdomainFetching(self):
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(self.crtshFetching(session), self.dnsdumpsterFetching(session))


class IPResolver:
    def __init__(self, subdomains):
        self.subdomains = subdomains
        self.results = []

    async def resolvingIP(self, domain):
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = "IP_NOT_FOUND"
        self.results.append({"subdomain": domain, "ip": ip})

    async def resolveALL(self):
        b = self.resolvingIP(domain)
        tasks = [self.resolvingIP(domain) for domain in self.subdomains]
        await asyncio.gather(*tasks)


class csvW:
    @staticmethod
    def saveCSV(results, filename="results.csv"):
        with open(filename, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["subdomain", "ip"])
            writer.writeheader()
            writer.writerows(results)
        print(f"Saved to {filename}")


class SubdomainFinder:
    def __init__(self, domain, DUMPSTER_API, DUMPSTER_LINK, CRTSH_LINK):
        self.domain = domain
        self.DUMPSTER_API = DUMPSTER_API
        self.DUMPSTER_LINK = DUMPSTER_LINK
        self.CRTSH_LINK = CRTSH_LINK

    async def run(self):
        fetcher = SubdomainFetcher(self.domain, self.DUMPSTER_API, self.DUMPSTER_LINK, self.CRTSH_LINK)
        await fetcher.subdomainFetching()

        resolver = IPResolver(fetcher.subdomains)
        await resolver.resolveALL()

        csvW.saveCSV(resolver.results)


domain = input("Enter the domain you want to search: ")
DUMPSTER_API = "fe16ff382dda396bbc4e12e8ccf0a1e25d65dd1092387447cb64eb547ef4f359"
DUMPSTER_LINK = "https://api.dnsdumpster.com/domain/"
CRTSH_LINK = "https://crt.sh/?q={}&output=json"

asyncio.run(SubdomainFinder(domain, DUMPSTER_API, DUMPSTER_LINK, CRTSH_LINK).run())