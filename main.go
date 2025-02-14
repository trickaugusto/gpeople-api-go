package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

func main() {
	ctx := context.Background()

	// Carrega as credenciais do cliente OAuth
	b, err := os.ReadFile("config/credentials.json")
	if err != nil {
		log.Fatalf("Não foi possível ler o arquivo de credenciais: %v", err)
	}

	// Cria a configuração OAuth2 com o escopo adequado e define o redirect URI
	config, err := google.ConfigFromJSON(b, people.ContactsReadonlyScope)
	if err != nil {
		log.Fatalf("Não foi possível criar a configuração OAuth2: %v", err)
	}

	// Obtém o cliente HTTP autenticado (usa o token salvo ou inicia o fluxo web)
	client := getClient(config)

	// Cria o serviço da API People
	srv, err := people.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Não foi possível criar o serviço da API People: %v", err)
	}

	// Exemplo: lista 10 contatos
	resp, err := srv.People.Connections.List("people/me").
		PageSize(10).
		PersonFields("names,emailAddresses").
		Do()
	if err != nil {
		log.Fatalf("Não foi possível recuperar os contatos: %v", err)
	}

	if len(resp.Connections) > 0 {
		fmt.Println("Lista dos 10 primeiros contatos:")
		for _, c := range resp.Connections {
			if len(c.Names) > 0 {
				fmt.Println(c.Names[0].DisplayName)
			}
		}
	} else {
		fmt.Println("Nenhum contato encontrado.")
	}
}

// getClient retorna um cliente HTTP autenticado.
// Se o token estiver salvo localmente (token.json), ele é utilizado;
// caso contrário, inicia o fluxo OAuth com servidor local para obter o token.
func getClient(config *oauth2.Config) *http.Client {
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// tokenFromFile lê o token salvo de um arquivo.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// saveToken salva o token em um arquivo.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Salvando token em: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Erro ao salvar o token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// getTokenFromWeb inicia um servidor HTTP local para capturar automaticamente o código de autorização.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	codeCh := make(chan string)

	// Cria um servidor HTTP para receber o código na rota "/"
	srv := &http.Server{Addr: ":8080"}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Extrai o parâmetro "code" da URL
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "Código não encontrado", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "Autorização recebida! Você pode fechar esta janela.")
		codeCh <- code
	})

	// Inicia o servidor em uma goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Falha ao iniciar o servidor: %v", err)
		}
	}()

	// Gera a URL de autorização
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Abra o seguinte link no seu navegador:\n%v\n", authURL)

	// Aguarda o código de autorização com timeout (2 minutos, por exemplo)
	var code string
	select {
	case code = <-codeCh:
		// Código recebido
	case <-time.After(2 * time.Minute):
		log.Fatalf("Tempo esgotado aguardando o código de autorização.")
	}

	// Após receber o código, encerra o servidor
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Erro ao encerrar o servidor: %v", err)
	}

	// Troca o código pelo token
	tok, err := config.Exchange(context.Background(), code)
	if err != nil {
		log.Fatalf("Erro ao trocar o código pelo token: %v", err)
	}
	return tok
}
