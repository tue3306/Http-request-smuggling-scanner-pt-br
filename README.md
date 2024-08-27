
### **Ferramenta de Detecção de HTTP Request Smuggling**

HTTP request smuggling é uma vulnerabilidade de alta severidade que é uma técnica onde um atacante "esmurra" uma requisição HTTP ambígua para contornar controles de segurança e obter acesso não autorizado para realizar atividades maliciosas. A vulnerabilidade foi descoberta em 2005 por [Watchfire](https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf) e mais tarde, em agosto de 2019, foi redescoberta por [James Kettle - (albinowax)](https://twitter.com/albinowax) e apresentada na [DEF CON 27](https://www.youtube.com/watch?v=w-eJM2Pc0KI) e [Black-Hat USA](https://www.youtube.com/watch?v=_A04msdplXs). Para saber mais sobre essa vulnerabilidade, você pode consultar seus bem documentados blogs de pesquisa no [site da Portswigger](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn). A ideia por trás desta ferramenta de segurança é detectar a vulnerabilidade de HRS (HTTP Request Smuggling) para um determinado host, e a detecção ocorre com base na técnica de atraso de tempo com as permutações fornecidas. 

<img src="screenshots/thumbnail.png"/>

### **Visão Geral Técnica**

A ferramenta é escrita em Python e para usá-la, você deve ter a versão 3.x do Python instalada em sua máquina local. Ela recebe como entrada uma URL ou uma lista de URLs que você deve fornecer em um arquivo de texto. Seguindo a técnica de detecção de vulnerabilidade HRS, a ferramenta possui cargas úteis incorporadas que incluem cerca de 37 permutações e cargas úteis de detecção para CL.TE e TE.CL. Para cada host fornecido, ela gera o objeto de requisição de ataque usando essas cargas úteis e calcula o tempo decorrido após receber a resposta para cada requisição, decidindo a vulnerabilidade. No entanto, na maioria das vezes, há chances de falsos positivos, então para confirmar a vulnerabilidade, você pode usar o Burp Suite Turbo Intruder e testar suas cargas úteis.

### **Consentimento de Segurança**

É bastante importante conhecer algumas das isenções legais antes de escanear qualquer alvo. Você deve ter autorização adequada antes de escanear qualquer alvo. Caso contrário, sugiro não usar esta ferramenta para escanear um alvo não autorizado, pois para detectar a vulnerabilidade, a ferramenta envia múltiplas cargas úteis várias vezes usando a opção (--retry), o que significa que se algo der errado, há a possibilidade de que o socket de backend possa ser envenenado com as cargas úteis e qualquer visitante genuíno desse site específico possa acabar vendo as cargas úteis envenenadas em vez de ver o conteúdo real do site. Portanto, recomendo fortemente tomar as precauções adequadas antes de escanear qualquer site alvo; caso contrário, você poderá enfrentar problemas legais.

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


