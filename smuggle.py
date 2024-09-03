import argparse
import json
import time
import os
import sys
import re
from termcolor import colored
from lib.Utils import Utils
from lib.Constants import Constants
from lib.SocketConnection import SocketConnection
from pathlib import Path
import colorama

colorama.init()

utils = Utils()
constants = Constants()

# Analisador de argumentos
parser = argparse.ArgumentParser(description='Ferramenta de detecção de vulnerabilidades de HTTP Request Smuggling')
parser.add_argument("-u", "--url", help="define a URL alvo")
parser.add_argument("-urls", "--urls", help="define a lista de URLs alvo, por exemplo (urls.txt)")
parser.add_argument("-t", "--timeout", help="define o tempo limite do socket, padrão - 10")
parser.add_argument("-m", "--method", help="define os Métodos HTTP, por exemplo (GET ou POST), padrão - POST")
parser.add_argument("-r", "--retry", help="define o número de tentativas para reexecutar o payload, padrão - 2")
args = parser.parse_args()


def hrs_detection(_host, _port, _path, _method, permute_type, content_length_key, te_key, te_value, smuggle_type,
                  content_length, payload, _timeout):
    headers = ''
    headers += '{} {} HTTP/1.1{}'.format(_method, _path, constants.crlf)
    headers += 'Host: {}{}'.format(_host, constants.crlf)
    headers += '{} {}{}'.format(content_length_key, content_length, constants.crlf)
    headers += '{}{}{}'.format(te_key, te_value, constants.crlf)
    smuggle_body = headers + payload

    permute_type = "[" + permute_type + "]"
    elapsed_time = "-"

    # Estilo de impressão
    _style_space_config = "{:<30}{:<25}{:<25}{:<25}{:<25}"
    _style_permute_type = colored(permute_type, constants.cyan, attrs=['bold'])
    _style_smuggle_type = colored(smuggle_type, constants.magenta, attrs=['bold'])
    _style_status_code = colored("-", constants.blue, attrs=['bold'])
    _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))
    _style_status = colored(constants.detecting, constants.green, attrs=['bold'])

    print(_style_space_config.format(_style_permute_type, _style_smuggle_type, _style_status_code, _style_elapsed_time,
                                     _style_status), end="\r", flush=True)

    start_time = time.time()

    try:
        connection = SocketConnection()
        connection.connect(_host, _port, _timeout)
        connection.send_payload(smuggle_body)

        response = connection.receive_data().decode("utf-8")
        end_time = time.time()

        if len(response.split()) > 0:
            status_code = response.split()[1]
        else:
            status_code = 'SEM RESPOSTA'
        _style_status_code = colored(status_code, constants.blue, attrs=['bold'])

        connection.close_connection()

        # A lógica de detecção é baseada na técnica de atraso de tempo, se o tempo decorrido for maior que o valor do tempo limite
        # então o status do host alvo mudará para [HRS → Vulnerável], mas na maioria das vezes pode haver
        # falso positivo. Para confirmar a vulnerabilidade, você pode usar o burp-suite turbo intruder e testar seus próprios
        # payloads. https://portswigger.net/web-security/request-smuggling/finding

        elapsed_time = str(round((end_time - start_time) % 60, 2)) + "s"
        _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))

        is_hrs_found = connection.detect_hrs_vulnerability(start_time, _timeout)

        # Se HRS encontrado, o payload será gravado no diretório de relatórios
        if is_hrs_found:
            _style_status = colored(constants.delayed_response_msg, constants.red, attrs=['bold'])
            _reports = constants.reports + '/{}/{}-{}{}'.format(_host, permute_type, smuggle_type, constants.extenstion)
            utils.write_payload(_reports, smuggle_body)
        else:
            _style_status = colored(constants.ok, constants.green, attrs=['bold'])
    except Exception as exception:
        elapsed_time = str(round((time.time() - start_time) % 60, 2)) + "s"
        _style_elapsed_time = "{}".format(colored(elapsed_time, constants.yellow, attrs=['bold']))

        error = f'{constants.dis_connected} → {exception}'
        _style_status = colored(error, constants.red, attrs=['bold'])

    print(_style_space_config.format(_style_permute_type, _style_smuggle_type, _style_status_code, _style_elapsed_time,
                                     _style_status))

    # Há um atraso de 1 segundo após a execução de cada payload
    time.sleep(1)


if __name__ == "__main__":
    # Se a versão do Python for menor que 3.x, o programa será encerrado
    if sys.version_info < (3, 0):
        print(constants.python_version_error_msg)
        sys.exit(1)

    try:
        # Imprime o cabeçalho da ferramenta
        utils.print_header()

        # As opções (url/urls) não são permitidas ao mesmo tempo
        if args.urls and args.url:
            print(constants.invalid_url_options)
            sys.exit(1)

        target_urls = list()
        if args.urls:
            urls = utils.read_target_list(args.urls)

            if constants.file_not_found in urls:
                print(f"[{args.urls}] não encontrado no seu diretório local")
                sys.exit(1)
            target_urls = urls

        if args.url:
            target_urls.append(args.url)

        for url in target_urls:
            result = utils.url_parser(url)
            try:
                json_res = json.loads(result)
                host = json_res['host']
                port = json_res['port']
                path = json_res['path']

                # Se o host for inválido, o programa será encerrado
                if host is None:
                    print(f"Host inválido - {host}")
                    sys.exit(1)

                method = args.method.upper() if args.method else "POST"
                pattern = re.compile('GET|POST')
                if not (pattern.match(method)):
                    print(constants.invalid_method_type)
                    sys.exit(1)

                timeout = int(args.timeout) if args.timeout else 10
                retry = int(args.retry) if args.retry else 2

                # Para detectar o HRS é necessário pelo menos 1 contagem de retry
                if retry == 0:
                    print(constants.invalid_retry_count)
                    sys.exit(1)

                square_left_sign = colored('[', constants.cyan, attrs=['bold'])
                plus_sign = colored("+", constants.green, attrs=['bold'])
                square_right_sign = colored(']', constants.cyan, attrs=['bold'])
                square_sign = "{}{}{:<16}".format(square_left_sign, plus_sign, square_right_sign)

                target_header_style_config = '{:<1}{}{:<25}{:<16}{:<10}'
                print(target_header_style_config.format('', square_sign,
                                                        colored("URL Alvo", constants.magenta, attrs=['bold']),
                                                        colored(":", constants.magenta, attrs=['bold']),
                                                        colored(url, constants.blue, attrs=['bold'])))
                print(target_header_style_config.format('', square_sign,
                                                        colored("Método", constants.magenta, attrs=['bold']),
                                                        colored(":", constants.magenta, attrs=['bold']),
                                                        colored(method, constants.blue, attrs=['bold'])))
                print(target_header_style_config.format('', square_sign,
                                                        colored("Retry", constants.magenta, attrs=['bold']),
                                                        colored(":", constants.magenta, attrs=['bold']),
                                                        colored(retry, constants.blue, attrs=['bold'])))
                print(target_header_style_config.format('', square_sign,
                                                        colored("Timeout", constants.magenta, attrs=['bold']),
                                                        colored(":", constants.magenta, attrs=['bold']),
                                                        colored(timeout, constants.blue, attrs=['bold'])))

                reports = os.path.join(str(Path().absolute()), constants.reports, host)
                print(target_header_style_config.format('', square_sign,
                                                        colored("Relatórios HRS", constants.magenta, attrs=['bold']),
                                                        colored(":", constants.magenta, attrs=['bold']),
                                                        colored(reports, constants.blue, attrs=['bold'])))
                print()

                payloads = open('payloads.json')
                data = json.load(payloads)

                payload_list = list()

                for permute in data[constants.permute]:
                    for d in data[constants.detection]:
                        # Com base no valor de retry, o mesmo payload será reexecutado
                        for _ in range(retry):
                            transfer_encoding_obj = permute[constants.transfer_encoding]
                            hrs_detection(host, port, path, method, permute[constants.type],
                                          permute[constants.content_length_key],
                                          transfer_encoding_obj[constants.te_key],
                                          transfer_encoding_obj[constants.te_value],
                                          d[constants.type],
                                          d[constants.content_length],
                                          d[constants.payload],
                                          timeout)
            except ValueError as _:
                print(result)
    except KeyboardInterrupt as e:
        print(e)
