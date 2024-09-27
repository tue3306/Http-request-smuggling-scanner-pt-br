# Tutorial: Ferramenta de Detecção de Vulnerabilidades de HTTP Request Smuggling

Este script Python é uma ferramenta projetada para detectar vulnerabilidades de HTTP Request Smuggling. Ele funciona em **sistemas Linux** e realiza a detecção através do envio de payloads específicos para o servidor alvo.

### **Instalação**

```
git clone https://github.com/anshumanpattnaik/http-request-smuggling.git
cd http-request-smuggling
pip3 install -r requirements.txt
```

### **Opções**

```
usage: smuggle.py [-h] [-u URL] [-urls URLS] [-t TIMEOUT] [-m METHOD]
                    [-r RETRY]

Ferramenta de detecção de vulnerabilidade HTTP Request Smuggling

argumentos opcionais:
  -h, --help            mostra esta mensagem de ajuda e sai
  -u URL, --url URL     define a URL alvo
  -urls URLS, --urls URLS
                        define a lista de URLs alvo, ou seja, (urls.txt)
  -t TIMEOUT, --timeout TIMEOUT
                        define o tempo limite do socket, padrão - 10
  -m METHOD, --method METHOD
                        define os Métodos HTTP, ou seja, (GET ou POST), padrão - POST
  -r RETRY, --retry RETRY
                        define o número de tentativas para reexecutar a carga útil, padrão - 2
```

### **Escanear uma URL**

```
python3 smuggle.py -u <URL>
```

### **Escanear lista de URLs**

```
python3 smuggle.py -urls <URLs.txt>
```

### **Importante**

Se você achar que a carga útil de detecção precisa ser alterada para torná-la mais precisa, você pode atualizar a carga útil no arquivo `payloads.json` na matriz de detecção.

```
"detection": [
	{
		"type": "CL.TE",
		"payload": "\r\n1\r\nZ\r\nQ\r\n\r\n",
		"content_length": 5
	},
	{
		"type": "TE.CL",
		"payload": "\r\n0\r\n\r\n\r\nG",
		"content_length": 6
	}
]
```


