import re

#BEGIN > regex declaration block

#request/response
requri_re = re.compile(r'(INVITE|OPTIONS|BYE|CANCEL|ACK|PRACK|UPDATE|REFER|SUBSCRIBE|NOTIFY|INFO|REGISTER) sip:(.*)@(.*):(\d+) SIP\/2\.0')
resuri_re = re.compile(r'SIP/2.0 (\d{3}) (.*)')

#headers
From_re = re.compile(r'From: (.*) <sip:(.*)@(.*)>(.*)')
To_re = re.compile(r'To:(.*)<sip:(.*)@(.*)>(.*)')
callId_re = re.compile(r'Call-ID: (.*)@(.*)')
via_re = re.compile(r'Via: SIP/2.0/(TCP|UDP|TLS) (.*):(.*);branch=(.*)')
cseq_re = re.compile(r'CSeq: (\d*) (INVITE|OPTIONS|BYE|CANCEL|ACK|PRACK|UPDATE|REFER|SUBSCRIBE|NOTIFY|INFO|REGISTER)')
ua_re = re.compile(r'User-Agent: (.*)')
supported_re = re.compile(r'Supported: (.*)')
allow_re = re.compile(r'Allow: (.*)')
maxf_re = re.compile(r'Max-Forwards: (\d*)')
contact_re = re.compile(r'Contact:(.*)<sip:(.*)@(.*):(.*)>')

#body
c_re = re.compile(r'c=IN IP4 (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
m_re = re.compile(r'm=(\S.*) (\d{1,5}) RTP/AVP (\d.*)')

#END > regex declaration block

class message:
    '''Questa classe definisce l'oggetto messaggio'''

    class Header:
        '''La porzione di messaggio che compone l'header SIP'''
        def __init__(self, headers_list = []):
            self.text = "\n".join(headers_list)
            via_list = []
            not_supported = []
            self.via = via_list
            self.not_supported = not_supported

            for line in headers_list:
                #Parsing for From:
                FROM = From_re.match(line)
                #Parsing for To:
                TO = To_re.match(line)
                #Parsing for Call-ID:
                CALLID = callId_re.match(line)
                #Parsing for Via:
                VIA = via_re.match(line)
                #Parsing for CSeq:
                CSEQ = cseq_re.match(line)
                #Parsing for User-Agent
                UA = ua_re.match(line)
                #Parsing for Supported
                SUPPORTED = supported_re.match(line)
                #Parsing for Allowed
                ALLOW = allow_re.match(line)
                #Parsing for Max-Forwards
                MAXF = maxf_re.match(line)
                #Parsing for Contact 
                CONTACT = contact_re.match(line)

                if FROM:
                    self.From = {'text': FROM.group(0),
                                 'label': FROM.group(1).strip(),
                                 'user': FROM.group(2),
                                 'realm': FROM.group(3),
                                 'aor': "SIP:"+FROM.group(2)+"@"+FROM.group(3)}
                elif TO:
                    self.to = {'text': TO.group(0),
                               'label': TO.group(1),
                               'user': TO.group(2),
                               'realm': TO.group(3),
                               'aor': "SIP:"+FROM.group(2)+"@"+FROM.group(3)}
                elif CALLID:
                    self.callId = {'text': CALLID.group(0),
                                   'uuid': CALLID.group(1),
                                   'realm': CALLID.group(2)}
                elif VIA:
                    self.via.append(VIA.group(0))
                elif CSEQ :
                    self.cseq = {'text': CSEQ.group(0),
                                 'number': CSEQ.group(1),
                                 'method': CSEQ.group(2)}
                elif UA:
                    self.user_agent = UA.group(1)
                elif SUPPORTED:
                    self.supported = {'text': SUPPORTED.group(0),
                                      'list': SUPPORTED.group(1).split(',')}
                elif ALLOW:
                    self.allow = {'text': ALLOW.group(0),
                                  'list': ALLOW.group(1).split(', ')}
                elif MAXF:
                    self.max_forward = {'text': MAXF.group(0),
                                  'list': int(MAXF.group(1))}
                elif CONTACT:
                    self.contact = {'text': CONTACT.group(0),
                                    'label': CONTACT.group(1).strip(),
                                    'number': CONTACT.group(2),
                                    'address': CONTACT.group(3),
                                    'port': CONTACT.group(4)}     
                else:
                    not_supported.append(line)
                ''' HEADERS RIMANENTI
                Date: Thu, 20 Jan 2022 16:43:16 GMT
                Min-SE:  1800
                Timestamp: 1642696996
                Expires: 180
                Allow-Events: telephone-event
                P-Asserted-Identity: "name" <sip:123456@1.1.1.1>
                Session-ID: f8eb9a6e41395134832c9f66f9158bc2;remote=00000000000000000000000000000000
                Session-Expires:  3600
                Content-Type: application/sdp
                Content-Disposition: session;handling=required
                Content-Length: 307
                '''

    class Body:
        '''La porzione di messaggio che compone il body SIP'''
        def __init__(self, body_list = []):
            self.text = "\n".join(body_list)
            
            a_list = []
            m_list = []
            self.a = a_list
            self.m = m_list

            for line in body_list:
                #Parsing for connection attribute:
                C = c_re.search(line)
                #Parsing for a= attribute:
                a_re = re.compile(r'a=.*')
                A = a_re.search(line)
                #Parsing for media attribute:
                M = m_re.search(line)                
                if C:
                    self.c = {'text': C.group(0),
                              'ip': C.group(1)}
                elif A:
                    a_list.append(A.group(0))
                elif M:
                    m_list.append({ 'text': M.group(0),
                                    'type': M.group(1),
                                    'port': M.group(2),
                                    'codecs': M.group(3)})

    class ReqURI:
        '''La porzione di messaggio che compone la ReqURi'''
        
        def __init__(self, message):
            self.text = message

            REQURI = requri_re.search(message)
            RESURI = resuri_re.search(message)
            if REQURI:
                self.method = REQURI.group(1)
                self.user = REQURI.group(2)
                self.proxy = REQURI.group(3)
                self.port = REQURI.group(4)
            if RESURI:
                code = int(RESURI.group(1))
                self.code = code
                self.reason = RESURI.group(2)
                if code <= 699: type = 'Global Failure'
                if code <= 599: type = 'Server Failure'
                if code <= 499: type = 'Client Failure'
                if code <= 399: type = 'Redirection'
                if code <= 299: type = 'Successful'
                if code <= 199: type = 'Provisional'
                self.type = type
                

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

class call:
    '''classe che definisce una chiamata come contatenazione di messaggi con medesimo call-id'''
    
    def import_from_file():
        pass

    def __init__(self, messages=[]):
        pass

