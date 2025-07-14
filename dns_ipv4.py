#!/usr/bin/env python3
import argparse
import socket
import statistics
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Tuple


class DNSSpeedTester:
    def __init__(self):
        # 常用的 DNS 服务器列表
        # https://github.com/easonjim/dns-server-list
        self.dns_servers = {
            'Google DNS 1': '8.8.8.8',
            'Google DNS 2': '8.8.4.4',
            'Cloudflare DNS 1': '1.1.1.1',
            'Cloudflare DNS 2': '1.0.0.1',
            'OpenDNS 1': '208.67.222.222',
            'OpenDNS 2': '208.67.220.220',
            'Quad9': '9.9.9.9',
            'Quad9 Secondary': '149.112.112.112',
            'Level3 DNS 1': '4.2.2.1',
            'Level3 DNS 2': '4.2.2.2',
            'Comodo DNS 1': '8.26.56.26',
            'Comodo DNS 2': '8.20.247.20',
            'CleanBrowsing': '185.228.168.9',
            'AdGuard DNS': '94.140.14.14',
            '114 DNS1': '114.114.114.114',
            '114 DNS2': '114.114.115.115',
            '阿里云 DNS1': '223.5.5.5',
            '阿里云 DNS2': '223.6.6.6',
            '腾讯云 DNS': '119.29.29.29',
            '百度 DNS': '180.76.76.76',
            '360 联通DNS1 ': '123.125.81.6',
            '360 联通DNS2': '140.207.198.6',
            '360 电信、移动、铁通DNS1': '101.226.4.6',
            '360 电信、移动、铁通DNS2': '218.30.118.6',
            '北京联通 DNS1': '123.123.123.123',
            '北京联通 DNS2': '123.123.123.124',
            '北京联通 DNS3': '202.106.0.20',
            '北京联通 DNS4': '202.106.195.68',
        }

        # 测试用的域名列表
        self.test_domains = [
            'baidu.com',
            'bing.com',
            'sogou.com',
            'so.com',
            'zhihu.com',
            'douban.com',
            'tieba.baidu.com',
            'xueqiu.com',
            'hupu.com',
            'guokr.com',
            'taobao.com',
            'tmall.com',
            'jd.com',
            'pinduoduo.com',
            'suning.com',
            'dangdang.com',
            'vip.com',
            'kaola.com',
            'yhd.com',
            'amazon.cn',
            'weibo.com',
            'qq.com',
            'weixin.qq.com',
            'toutiao.com',
            'xiaohongshu.com',
            'douyin.com',
            'kuaishou.com',
            'bilibili.com',
            'iqiyi.com',
            'youku.com',
            'mgtv.com',
            'pptv.com',
            'acfun.cn',
            'huya.com',
            'douyu.com',
            'sina.com.cn',
            '163.com',
            'sohu.com',
            'people.com.cn',
            'xinhuanet.com',
            'ifeng.com',
            'china.com',
            'cctv.com',
            'gmw.cn',
            'thepaper.cn',
            'caixin.com',
            '36kr.com',
            'csdn.net',
            'oschina.net',
            'cnblogs.com',
            'jianshu.com',
            'segmentfault.com',
            '51cto.com',
            'aliyun.com',
            'qcloud.com',
            'huaweicloud.com',
            '189.cn',
            'mi.com',
            'huawei.com',
            'oppo.com',
            'vivo.com',
            'meituan.com',
            'dianping.com',
            'ele.me',
            'ctrip.com',
            'qunar.com',
            '12306.cn',
            '58.com',
            'ganji.com',
            'zufang.com',
            'autohome.com.cn',
            'bitauto.com',
            'che168.com',
            'anjuke.com',
            'lianjia.com',
            'alipay.com',
            'unionpay.com',
            'icbc.com.cn',
            'ccb.com',
            'abcchina.com',
            'boc.cn',
            'cmbchina.com',
            'pingan.com',
            'ximalaya.com',
            'qingting.fm',
            'lizhi.fm',
            'kugou.com',
            'kuwo.cn',
            'qqmusic.com',
            'netease.com',
            '7k7k.com',
            '4399.com',
            '17173.com',
            'a9vg.com',
            'tgbus.com',
            '3dmgame.com',
            'zhangyue.com',
            'qidian.com',
            'zongheng.com',
            '17k.com',
            'jjwxc.net',
            'gov.cn',
            'edu.cn',
            'mooc.cn',
            'chinadaily.com.cn',
            'cri.cn',
            'china.org.cn'
        ]

    def create_dns_query(self, domain: str) -> bytes:
        """创建 DNS 查询数据包"""
        # DNS 查询 ID
        query_id = 0x1234

        # DNS 标志位：标准查询，递归查询
        flags = 0x0100

        # 问题数量
        questions = 1

        # 其他字段都为0
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        # 构建 DNS 头部
        header = struct.pack('!HHHHHH', query_id, flags, questions,
                             answer_rrs, authority_rrs, additional_rrs)

        # 构建查询问题部分
        question = b''
        for part in domain.split('.'):
            question += struct.pack('!B', len(part)) + part.encode()
        question += b'\x00'  # 域名结束标志

        # 查询类型 A 记录 (0x0001) 和查询类 IN (0x0001)
        question += struct.pack('!HH', 0x0001, 0x0001)

        return header + question

    def test_dns_server(self, server_name: str, server_ip: str,
                        domain: str, timeout: float = 2.0) -> Tuple[str, float]:
        """测试单个 DNS 服务器的响应时间"""
        try:
            # 创建 UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # 创建 DNS 查询
            query = self.create_dns_query(domain)

            # 记录开始时间
            start_time = time.time()

            # 发送查询
            sock.sendto(query, (server_ip, 53))

            # 接收响应
            response, _ = sock.recvfrom(1024)

            # 计算响应时间
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # 转换为毫秒

            sock.close()

            return server_name, response_time

        except (socket.timeout, socket.error) as e:
            return server_name, float('inf')  # 超时或错误返回无穷大

    def test_multiple_queries(self, server_name: str, server_ip: str,
                              num_queries: int = 5) -> Dict[str, float]:
        """对单个 DNS 服务器进行多次查询测试"""
        results = []

        for domain in self.test_domains[:num_queries]:
            _, response_time = self.test_dns_server(server_name, server_ip, domain)
            if response_time != float('inf'):
                results.append(response_time)

        if not results:
            return {
                'avg': float('inf'),
                'min': float('inf'),
                'max': float('inf'),
                'median': float('inf'),
                'success_rate': 0
            }

        return {
            'avg': statistics.mean(results),
            'min': min(results),
            'max': max(results),
            'median': statistics.median(results),
            'success_rate': len(results) / num_queries * 100
        }

    def run_speed_test(self, num_queries: int = 5, max_workers: int = 20) -> Dict:
        """运行 DNS 速度测试"""
        print(f"开始测试 {len(self.dns_servers)} 个 DNS 服务器...")
        print(f"每个服务器测试 {num_queries} 个查询")
        print("-" * 60)

        results = {}

        # 使用线程池进行并发测试
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有测试任务
            future_to_server = {
                executor.submit(self.test_multiple_queries, name, ip, num_queries): name
                for name, ip in self.dns_servers.items()
            }

            # 收集结果
            for future in as_completed(future_to_server):
                server_name = future_to_server[future]
                try:
                    result = future.result()
                    results[server_name] = result

                    # 实时显示结果
                    if result['avg'] == float('inf'):
                        print(f"{server_name:<20} | 超时或错误")
                    else:
                        print(f"{server_name:<20} | 平均: {result['avg']:.2f}ms | "
                              f"最快: {result['min']:.2f}ms | 成功率: {result['success_rate']:.0f}%")

                except Exception as e:
                    print(f"{server_name:<20} | 测试失败: {e}")
                    results[server_name] = {
                        'avg': float('inf'),
                        'min': float('inf'),
                        'max': float('inf'),
                        'median': float('inf'),
                        'success_rate': 0
                    }

        return results

    def print_summary(self, results: Dict):
        """打印测试结果总结"""
        print("\n" + "=" * 60)
        print("测试结果总结")
        print("=" * 60)

        # 过滤掉失败的服务器
        valid_results = {k: v for k, v in results.items()
                         if v['avg'] != float('inf') and v['success_rate'] > 0}

        if not valid_results:
            print("没有可用的 DNS 服务器")
            return

        # 按平均响应时间排序
        sorted_results = sorted(valid_results.items(), key=lambda x: x[1]['avg'])

        print(f"{'排名':<4} {'DNS 服务器':<20} {'平均响应时间':<12} {'最快响应':<10} {'成功率':<8}")
        print("-" * 60)

        for i, (server_name, stats) in enumerate(sorted_results[:10], 1):
            print(f"{i:<4} {server_name:<20} {stats['avg']:.2f}ms{'':<6} "
                  f"{stats['min']:.2f}ms{'':<4} {stats['success_rate']:.0f}%")

        # 显示最快的 DNS 服务器
        if sorted_results:
            fastest_server, fastest_stats = sorted_results[0]
            print(f"\n🏆 最快的 DNS 服务器: {fastest_server}")
            print(f"   平均响应时间: {fastest_stats['avg']:.2f}ms")
            print(f"   最快响应时间: {fastest_stats['min']:.2f}ms")
            print(f"   成功率: {fastest_stats['success_rate']:.0f}%")

    def add_custom_dns(self, name: str, ip: str):
        """添加自定义 DNS 服务器"""
        self.dns_servers[name] = ip

    def remove_dns(self, name: str):
        """移除 DNS 服务器"""
        if name in self.dns_servers:
            del self.dns_servers[name]


def main():
    parser = argparse.ArgumentParser(description='DNS 速度测试工具')
    parser.add_argument('-q', '--queries', type=int, default=5,
                        help='每个 DNS 服务器的查询次数 (默认: 5)')
    parser.add_argument('-w', '--workers', type=int, default=20,
                        help='并发线程数 (默认: 20)')
    parser.add_argument('-a', '--add-dns', nargs=2, metavar=('NAME', 'IP'),
                        help='添加自定义 DNS 服务器')
    parser.add_argument('-r', '--remove-dns', metavar='NAME',
                        help='移除指定的 DNS 服务器')
    parser.add_argument('--list', action='store_true',
                        help='列出所有 DNS 服务器')

    args = parser.parse_args()

    # 创建测试器
    tester = DNSSpeedTester()

    # 添加自定义 DNS
    if args.add_dns:
        tester.add_custom_dns(args.add_dns[0], args.add_dns[1])
        print(f"已添加 DNS 服务器: {args.add_dns[0]} ({args.add_dns[1]})")

    # 移除 DNS
    if args.remove_dns:
        tester.remove_dns(args.remove_dns)
        print(f"已移除 DNS 服务器: {args.remove_dns}")

    # 列出所有 DNS 服务器
    if args.list:
        print("可用的 DNS 服务器:")
        for name, ip in tester.dns_servers.items():
            print(f"  {name}: {ip}")
        return

    # 运行测试
    try:
        results = tester.run_speed_test(args.queries, args.workers)
        tester.print_summary(results)
    except KeyboardInterrupt:
        print("\n测试被用户中断")
    except Exception as e:
        print(f"测试过程中发生错误: {e}")


if __name__ == "__main__":
    main()
