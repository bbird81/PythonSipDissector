import re

class message:
    '''Questa classe definisce l'oggetto messaggio'''

    class Header:
        '''La porzione di messaggio che compone l'header SIP'''
        def __init__(self, headers_list = []):
            self.text = "\n".join(headers_list)
            for line in headers_list:
                #Parsing for From:
                From_re = re.compile(r'From: (.*) <sip:(.*)@(.*)>(.*)')
                From = From_re.search(line)
                if From :
                    self.From = From.group(0)
                    self.From_label = From.group(1)
                    self.From_user = From.group(2)
                    self.From_realm = From.group(3)
                #Parsing for To:
                To_re = re.compile(r'To: (.*) <sip:(.*)@(.*)>(.*)')
                To = To_re.search(line)
                if To :
                    self.to = To.group(0)
                    self.to_label = To.group(1)
                    self.to_user = To.group(2)
                    self.to_realm = To.group(3)
                #Parsing for Call-ID:
                callId_re = re.compile(r'Call-ID: (.*)@(.*)')
                CallID = callId_re.search(line)
                if CallID :
                    self.callId = CallID.group(0)
                    self.callId_uuid = CallID.group(1)
                    self.callId_realm = CallID.group(2)

    class Body:
        '''La porzione di messaggio che compone il body SIP'''
        def __init__(self, body_list = []):
            self.text = "\n".join(body_list)
            for line in body_list:
                #Parsing for connection attribute:
                c_re = re.compile(r'c=IN IP4 (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                C = c_re.search(line)
                if C:
                    self.c = C.group(0)
                    self.c_ip = C.group(1)

    class ReqURI:
        '''La porzione di messaggio che compone la ReqURi'''
        
        def __init__(self, message):
            self.text = message
            requri_re = re.compile(r'(INVITE|OPTIONS|BYE|CANCEL|ACK|PRACK|UPDATE|REFER|SUBSCRIBE|NOTIFY|INFO|REGISTER) sip:(.*)@(.*):(\d+) SIP\/2\.0')
            REQURI = requri_re.search(message)
            self.method = REQURI.group(1)
            self.user = REQURI.group(2)
            self.proxy = REQURI.group(3)
            self.port = REQURI.group(4)

    def __init__(self, message):
        self.message = message #importo l'intero messaggio
        lines_re = re.compile(r'\n') #regex che individua le singole linee
        lines = lines_re.split(message) #array di linee
        self.requri = self.ReqURI(lines.pop(0)) #la prima linea è la req-uri, la passo e la rimuovo
        body_re = re.compile(r'^\S=.*')
        header_line_list = []
        body_line_list = []
        for line in lines:
            if body_re.match(line):
                body_line_list.append(line)
            else:
                header_line_list.append(line)
        self.header = self.Header(header_line_list)
        self.body = self.Body(body_line_list)



