#!/usr/bin/env python3
import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import httpx

# pip3 install httpx dnspython
DOH_SERVERS = {
    # Cloudflare（隐私优先，速度快）
    "Cloudflare IPv4": "https://1.1.1.1/dns-query",
    "Cloudflare IPv4 #2": "https://1.0.0.1/dns-query",

    # Google（全球可用，稳定）
    "Google DoH IPv4": "https://8.8.8.8/dns-query",
    "Google DoH IPv4 #2": "https://8.8.4.4/dns-query",
}

# 使用的美国常见网址（可以根据需要自行调整）
US_DOMAINS = [
                 "google.com", "facebook.com", "youtube.com", "amazon.com", "yahoo.com", "reddit.com", "wikipedia.org",
                 "ebay.com", "linkedin.com", "netflix.com", "espn.com", "cnn.com", "foxnews.com", "nytimes.com",
                 "msn.com",
                 "apple.com", "microsoft.com", "imdb.com", "pinterest.com", "instagram.com", "paypal.com", "target.com",
                 "walmart.com", "bestbuy.com", "home depot.com", "lowes.com", "costco.com", "macys.com", "kohls.com",
                 "npr.org",
                 "weather.com", "accuweather.com", "hulu.com", "zoom.us", "dropbox.com", "stackoverflow.com",
                 "github.com",
                 "twitch.tv", "cbsnews.com", "nbcnews.com", "abcnews.go.com", "bbc.com", "usatoday.com", "forbes.com",
                 "bloomberg.com", "wsj.com", "marketwatch.com", "investopedia.com", "theverge.com", "techcrunch.com",
                 "engadget.com",
                 "wired.com", "cnet.com", "businessinsider.com", "buzzfeed.com", "quora.com", "fandom.com",
                 "tripadvisor.com",
                 "booking.com", "airbnb.com", "expedia.com", "kayak.com", "zillow.com", "realtor.com", "indeed.com",
                 "glassdoor.com",
                 "craigslist.org", "etsy.com", "wayfair.com", "chewy.com", "overstock.com", "nike.com", "adidas.com",
                 "underarmour.com",
                 "dickssportinggoods.com", "oldnavy.com", "gap.com", "uniqlo.com", "ae.com", "hollisterco.com",
                 "abercrombie.com",
                 "shein.com", "fashionnova.com", "poshmark.com", "thredup.com", "sephora.com", "ulta.com",
                 "glossier.com", "macys.com",
                 "nordstrom.com", "jcpenney.com", "bjs.com", "samsclub.com", "kroger.com", "wholefoodsmarket.com",
                 "traderjoes.com",
                 "publix.com", "safeway.com", "wegmans.com", "aldi.us", "harborfreight.com", "acehardware.com",
                 "grainger.com"
             ][:100]  # 限定前100个


class DoHSpeedTester:
    def __init__(self, doh_servers: Dict[str, str], domains: List[str]):
        self.doh_servers = doh_servers
        self.domains = domains

    def build_dns_query(self, domain: str) -> bytes:
        """构造一个原始 DNS 查询（二进制形式）"""
        import dns.message
        query = dns.message.make_query(domain, dns.rdatatype.A)
        return query.to_wire()

    def test_doh_server(self, server_name: str, url: str, domain: str, timeout=3.0) -> float:
        """测试 DoH 响应时间（毫秒），失败返回 inf"""
        headers = {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message"
        }
        query = self.build_dns_query(domain)

        try:
            start = time.time()
            resp = httpx.post(url, content=query, headers=headers, timeout=timeout)
            resp.raise_for_status()
            duration = (time.time() - start) * 1000  # ms
            return duration
        except Exception:
            return float("inf")

    def test_server_on_domains(self, name: str, url: str, count: int) -> Dict:
        times = []

        for domain in self.domains[:count]:
            resp_time = self.test_doh_server(name, url, domain)
            if resp_time != float("inf"):
                times.append(resp_time)

        if not times:
            return {
                "avg": float("inf"),
                "min": float("inf"),
                "max": float("inf"),
                "median": float("inf"),
                "success_rate": 0.0
            }

        return {
            "avg": statistics.mean(times),
            "min": min(times),
            "max": max(times),
            "median": statistics.median(times),
            "success_rate": len(times) / count * 100
        }

    def run(self, domain_count: int = 20, max_workers: int = 10):
        print(f"测试 DoH 服务器，域名数: {domain_count}")
        print("-" * 60)

        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.test_server_on_domains, name, url, domain_count): name
                for name, url in self.doh_servers.items()
            }

            for future in as_completed(futures):
                name = futures[future]
                try:
                    stats = future.result()
                    results[name] = stats
                    if stats['avg'] == float("inf"):
                        print(f"{name:<20} | 超时/失败")
                    else:
                        print(
                            f"{name:<20} | 平均: {stats['avg']:.2f}ms | 最快: {stats['min']:.2f}ms | 成功率: {stats['success_rate']:.0f}%")
                except Exception as e:
                    print(f"{name:<20} | 错误: {e}")

        return results

    def print_summary(self, results: Dict):
        print("\n测试总结")
        print("=" * 60)
        valid = {k: v for k, v in results.items() if v['avg'] != float('inf')}
        sorted_results = sorted(valid.items(), key=lambda x: x[1]['avg'])

        print(f"{'排名':<4} {'服务器':<20} {'平均(ms)':<10} {'最小(ms)':<10} {'成功率(%)':<10}")
        for i, (name, stats) in enumerate(sorted_results, 1):
            print(f"{i:<4} {name:<20} {stats['avg']:.2f}      {stats['min']:.2f}      {stats['success_rate']:.0f}")

        if sorted_results:
            best = sorted_results[0]
            print(f"\n🏆 最快服务器: {best[0]}, 平均响应: {best[1]['avg']:.2f}ms")


def main():
    parser = argparse.ArgumentParser(description="DoH DNS 速度测试")
    parser.add_argument("-n", "--num", type=int, default=20, help="每个服务器测试的域名数量")
    parser.add_argument("-w", "--workers", type=int, default=10, help="并发线程数")
    args = parser.parse_args()

    tester = DoHSpeedTester(DOH_SERVERS, US_DOMAINS)
    results = tester.run(domain_count=args.num, max_workers=args.workers)
    tester.print_summary(results)


if __name__ == "__main__":
    main()
