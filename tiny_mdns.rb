#!/usr/bin/ruby
#
# tiny mDNS server for old Ruby 1.8
#
# 2021-10-05 programed by NAKAUE,T
#

#require 'optparse'
require 'socket'
require 'ipaddr'


# Ruby 1.8.5/1.9.0にはArray#to_hがまだない
if !([].methods.include?(:to_h))
    class Array
        def to_h
            self.inject({}) {|result, item| result.merge({item.first => item.last})}
        end
    end
end


# 自身のIPアドレスを取得する
# (インタフェースが複数あると失敗するかも)
def get_my_address
    sock = UDPSocket.new
    sock.connect('128.0.0.0', 7)
    addr = Socket.unpack_sockaddr_in(sock.getsockname)[1]
    sock.close
    addr
end


# DNSパケットの解析
module DNSpacketAnalyzer

    # Headerセクションの解析
    def getHeader!(data)
        result = [
            :ID, :TMP, :QDCOUNT, :ANCOUNT, :NSCOUNT, :ARCOUNT
        ].zip(
            data.slice!(0, 12).unpack('n*')
        ).to_h

        result.merge!([
            :QR, :OPCODE, :AA, :TC, :RD, :RA, :Z, :AD, :CD, :RCODE
        ].zip(
            result[:TMP].to_s(2).rjust(16, '0').unpack('AA4AAAAAAAA4').map{|x| x.to_i(2)}
        ).to_h)

        result.delete(:TMP)

        return result
    end


    # ドメイン名の解析
    def getDomain!(data)
        domain = []
        while (len = data.slice!(0, 1).unpack('C').first) != 0
            if len >= 0xc0
                # メッセージ圧縮
                len = ((len & 0x3f) << 8) + data.slice!(0, 1).unpack('C').first
                domain = ['@' + len.to_s]
                break
            end
            domain << data.slice!(0, len)
        end

        return domain.join('.')
    end


    # Questionセクションの解析
    def getQuestion!(data)
        return nil if data.size == 0

        return [
            :DOMAIN, :TYPE, :CLASS
        ].zip(
            [getDomain!(data)] + data.slice!(0, 4).unpack('nn')
        ).to_h
    end


    # Answerセクションの解析
    def getAnswer!(data)
        return nil if data.size == 0

        result = [
            :DOMAIN, :TYPE, :CLASS, :TTL, :RDLENGTH
        ].zip(
            [getDomain!(data)] + data.slice!(0, 10).unpack('nnNn')
        ).to_h

        return result.merge({
            :RDATA => data.slice!(0, result[:RDLENGTH])
        })
    end


    # Headerセクションの組立
    def buildHeader(source)
        source[:TMP] = [
            :QR, :OPCODE, :AA, :TC, :RD, :RA, :Z, :AD, :CD, :RCODE
        ].zip([
            1, 4, 1, 1, 1, 1, 1, 1, 1, 4
        ]).map{|key|
            source[key.first].to_s(2).rjust(key.last, '0')
        }.join.to_i(2)

        return [
            :ID, :TMP, :QDCOUNT, :ANCOUNT, :NSCOUNT, :ARCOUNT
        ].map{|key|
            source[key]
        }.pack('n*')
    end


    # ドメインの組立
    def buildDomain(domain)
        return [0xc000 + domain[1..-1].to_i].pack('n') if domain[0..0] == '@'

        return domain.split('.').map{|str|
            [str.size].pack('C') + str
        }.join + "\x00"
    end


    # Questionセクションの組立
    def buildQuestion(source)
        return '' if !source

        return buildDomain(source[:DOMAIN]) + [
            :TYPE, :CLASS
        ].map{|key|
            source[key]
        }.pack('n*')
    end


    # Answerセクションの組立
    def buildAnswer(source)
        return '' if !source

        source[:RDLENGTH] = source[:RDATA].size

        return buildDomain(source[:DOMAIN]) + [
            :TYPE, :CLASS, :TTL, :RDLENGTH
        ].map{|key|
            source[key]
        }.pack('nnNn') + source[:RDATA]
    end

end


# DNSパケット
class DNSpacket
    include DNSpacketAnalyzer

    attr_accessor(:header_section)
    attr_accessor(:question_section)
    attr_accessor(:answer_section)
    attr_accessor(:authority_section)
    attr_accessor(:additional_section)


    def initialize(data = nil)

        if !data
            @header_section = {
                :ID => 0,
                :QR => 0,
                :OPCODE => 0,
                :AA => 0,
                :TC => 0,
                :RD => 0,
                :RA => 0,
                :Z => 0,
                :AD => 0,
                :CD => 0,
                :RCODE => 0
            }
            @question_section = nil
            @answer_section = nil
            @authority_section = nil
            @additional_section = nil
        else
            self.analyze(data)
        end

    end


    # パケットの解析
    def analyze(data)
        @header_section = getHeader!(data)
        @question_section   = (@header_section[:QDCOUNT] > 0) ? getQuestion!(data) : nil
        @answer_section     = (@header_section[:ANCOUNT] > 0) ? getAnswer!(data) : nil
        @authority_section  = (@header_section[:NSCOUNT] > 0) ? getAnswer!(data) : nil
        @additional_section = (@header_section[:ARCOUNT] > 0) ? getAnswer!(data) : nil
    end


    # 応答からアドレス取得
    # 先にanalyzeを行っておく
    def get_address()
        @answer_section[:RDATA].unpack('C*')
    end


    # パケットの組立
    def buildPacket()
        @header_section[:QDCOUNT] = @question_section   ? 1 : 0
        @header_section[:ANCOUNT] = @answer_section     ? 1 : 0
        @header_section[:NSCOUNT] = @authority_section  ? 1 : 0
        @header_section[:ARCOUNT] = @additional_section ? 1 : 0

        return buildHeader(@header_section) +
            buildQuestion(@question_section) +
            buildAnswer(@answer_section) +
            buildAnswer(@authority_section) +
            buildAnswer(@additional_section)
    end

end


# mDNSのアドレス
mdns_addr = ['224.0.0.251', 5353]

# 自分のインタフェースのアドレス
if_addr = IPAddr.new(get_my_address()).hton

# 自分のホスト名
my_hostname = Socket.gethostname + '.local'

# 対応しているクエリ
query = DNSpacket.new
query.question_section = {
    :DOMAIN => my_hostname,
    :TYPE => 1,
    :CLASS => 1
}


# Ruby 1.8.5/1.9.0にはARGV.getoptsがまだない
#params = ARGV.getopts("D", "query")
params = [
    '-D',
    '--query'
].map {|opt|
    [opt.sub(/^-+/, ''), (ARGV.delete(opt) != nil) ? true : false]
}.to_h

if params['query']
    # queryモード

    # 質問パケット
    query.question_section[:DOMAIN] = ARGV[0] if ARGV[0]
    puts "query #{query.question_section[:DOMAIN]}"
    query_packet = query.buildPacket()

    sock = UDPSocket.open()
    sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_MULTICAST_IF, if_addr)
    sock.send(query_packet, 0, mdns_addr[0], mdns_addr[1])

    data, from_addr = sock.recvfrom(65535)                  # タイムアウトが未実装
    sock.close

    packet = DNSpacket.new(data)
    puts "answer #{packet.get_address.map{|x| x.to_s}.join('.')}"
else
    # serverモード

    if params['D']
        # daemonモード
        Process.daemon
        open("/var/run/#{File.basename($0, '.rb')}.pid", 'w') {|f| f.puts(Process.pid)}
    end

    puts 'server wait' if !params['D']

    # 照合用の質問パケット
    query_packet = query.buildPacket()

    # 回答用のパケット
    answer = DNSpacket.new
    answer.header_section[:QR] = 1
    answer.header_section[:AA] = 1
    answer.answer_section = {
        :DOMAIN => my_hostname,
        :TYPE => 1,
        :CLASS => 1,
        :TTL => 300,
        :RDLENGTH => 4, 
        :RDATA => if_addr
    }
    answer_packet = answer.buildPacket()

    sock = UDPSocket.open()
    sock.bind('0.0.0.0', mdns_addr[1])
    mreq = IPAddr.new(mdns_addr[0]).hton + IPAddr.new('0.0.0.0').hton
    sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, mreq)

    while true
        data, from_addr = sock.recvfrom(65535)
        answer_packet[0..1] = data[0..1]
        data[0..1] = "\000\000"

        if data == query_packet
            # 応答可能なパケット
            puts "query from #{from_addr[2]}:#{from_addr[1]}" if !params['D']
            answer_addr = Socket.pack_sockaddr_in(from_addr[1], from_addr[2])
            sock.send(answer_packet, 0, answer_addr)
        end
    end

    sock.close

end

