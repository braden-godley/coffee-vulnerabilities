package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	godotenv "github.com/joho/godotenv"
	"github.com/samber/lo"
	openai "github.com/sashabaranov/go-openai"
	terminal "github.com/terminaldotshop/terminal-sdk-go"
	"github.com/terminaldotshop/terminal-sdk-go/option"
)

const ScoreThreshold = 9.0

type CVEResponse struct {
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Cve struct {
		Id           string        `json:"id"`
		Published    string        `json:"published"`
		Descriptions []Description `json:"descriptions"`
		Metrics      struct {
			CvssMetricV31 []struct {
				CvssData CvssData `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CvssMetricV40 []struct {
				CvssData CvssData `json:"cvssData"`
			} `json:"cvssMetricV40"`
			CvssMetricV2 []struct {
				CvssData CvssData `json:"cvssData"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
	} `json:"cve"`
}

type CvssData struct {
	BaseScore float64 `json:"baseScore"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type ChatResponse struct {
	Thinking string `xml:"thinking"`
	Company  struct {
		Name           string `xml:"name,attr"`
		Address        string `xml:"address,attr"`
		AddressLineTwo string `xml:"addressLineTwo,attr"`
		City           string `xml:"city,attr"`
		State          string `xml:"state,attr"`
		Zip            string `xml:"zip,attr"`
		Country        string `xml:"country,attr"`
	} `xml:"company"`
}

func main() {
	log.SetPrefix("coffee-vulns: ")
	log.SetFlags(0)

	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	vulns, err := getVulnerabilities()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Received %d CVEs", len(vulns.Vulnerabilities))

	critical := lo.Filter(vulns.Vulnerabilities, func(v Vulnerability, _ int) bool {
		return v.getBaseScore() > ScoreThreshold
	})

	for _, v := range critical {
		log.Printf("Id: %s", v.Cve.Id)
		err := v.handleVulnerability()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("")
	}

	log.Printf("Found %d/%d CVEs with score at least %f", len(critical), len(vulns.Vulnerabilities), ScoreThreshold)
}

func (v Vulnerability) handleVulnerability() error {
	resp, err := v.getChatResponse()
	if err != nil {
		return err
	}

	log.Println(resp)

	apiKey, err := getTerminalApiKey()
	if err != nil {
		return err
	}

	client := terminal.NewClient(
		option.WithBearerToken(apiKey),
		option.WithBaseURL("https://api.dev.terminal.shop/"),
	)

	products, err := client.Product.List(context.TODO())
	if err != nil {
		return err
	}

	possibleProducts := lo.Filter(products.Data, func(product terminal.Product, _ int) bool {
		return product.Name != "404" && // Don't send them decaf, they need caffeine!
			product.Subscription != terminal.ProductSubscriptionRequired // Can't send them a subscription.
	})

	randomProduct := lo.Sample(possibleProducts)

	log.Println("Chose randomly:", randomProduct.Name)

	addressResponse, err := client.Address.New(
		context.TODO(),
		terminal.AddressNewParams{
			Name:     terminal.F(resp.Company.Name),
			Street1:  terminal.F(resp.Company.Address),
			Street2:  terminal.F(resp.Company.AddressLineTwo),
			City:     terminal.F(resp.Company.City),
			Province: terminal.F(resp.Company.State),
			Country:  terminal.F(resp.Company.Country),
			Zip:      terminal.F(resp.Company.Zip),
		},
	)
	if err != nil {
		return err
	}
	addressId := addressResponse.Data

	cardResponse, err := client.Card.New(
		context.TODO(),
		terminal.CardNewParams{
			Token: terminal.F("tok_1N3T00LkdIwHu7ixt44h1F8k"),
		},
	)
	if err != nil {
		return err
	}
	cardId := cardResponse.Data

	orderResponse, err := client.Order.New(
		context.TODO(),
		terminal.OrderNewParams{
			CardID:    terminal.F(cardId),
			AddressID: terminal.F(addressId),
		},
	)
	if err != nil {
		return err
	}

	log.Println("Ordered")
	log.Println(orderResponse)

	return nil
}

func getVulnerabilities() (*CVEResponse, error) {
	end := time.Now()
	start := end.Add(-30 * time.Hour)

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&pubStartDate=%v&pubEndDate=%v", start.Format(time.RFC3339), end.Format(time.RFC3339))

	log.Printf("Getting %v", url)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response CVEResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (v Vulnerability) getBaseScore() float64 {
	metrics := v.Cve.Metrics
	if len(metrics.CvssMetricV40) > 0 {
		return metrics.CvssMetricV40[0].CvssData.BaseScore
	}

	if len(metrics.CvssMetricV31) > 0 {
		return metrics.CvssMetricV31[0].CvssData.BaseScore
	}

	if len(metrics.CvssMetricV2) > 0 {
		return metrics.CvssMetricV2[0].CvssData.BaseScore
	}

	return 0
}

func (v Vulnerability) getDescription() (string, error) {
	if desc, ok := lo.Find(v.Cve.Descriptions, func(desc Description) bool {
		return desc.Lang == "en"
	}); ok {
		return desc.Value, nil
	} else {
		return "", errors.New("no description")
	}
}

func (v Vulnerability) getChatResponse() (*ChatResponse, error) {
	apiKey, err := getOpenAIApiKey()
	if err != nil {
		return nil, err
	}
	client := openai.NewClient(apiKey)

	desc, err := v.getDescription()
	if err != nil {
		return nil, err
	}

	message := fmt.Sprintf(`I am going to give you a description of a severe CVE vulnerability.
        Please describe to me which companies you think are most likely affected by this vulnerability, and choose the most important one.
        We want to send them coffee as a consolation for the stress and effort this new vulnerability is going to place on their engineers.
        So please also include their physical address so that we can send them this coffee!

        Here is an example response. Please format your response similarly, using XML with the same structure. Don't wrap your response in backticks

        <response>
            <thinking>
                Because this vulnerability affects PHP, I think that I should focus on large companies that use PHP. I know of a few companies:
                - Facebook: Originally built with PHP, Facebook has developed its own version called Hack, which is a derivative of PHP.
                - Wikipedia: The platform runs on MediaWiki, which is primarily written in PHP.
                - WordPress: While not a company per se, WordPress powers a significant portion of the web and is built on PHP. Many large organizations use WordPress for their websites.
                - Slack: The messaging platform uses PHP for some of its backend services.
                - Tumblr: This microblogging platform is also built using PHP.
                - Mailchimp: The email marketing service utilizes PHP in its backend.
                - Yahoo: Parts of Yahoo's services are built using PHP.
                - Flickr: The photo-sharing platform is another example of a site that uses PHP.
                Facebook is probably the largest company, so I'll give that as my response.
            </thinking>
            <company name="Facebook" address="1 Hacker Way" addressLineTwo="" city="Menlo Park" state="CA" country="US" zip="94025"></company>
        </response>

        Here is the vulnerability description: %s
    `, desc)

	chat, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4oMini,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: message,
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}

	content := chat.Choices[0].Message.Content

	var response ChatResponse
	err = xml.Unmarshal([]byte(content), &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func getOpenAIApiKey() (string, error) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		return "", errors.New("invalid api key")
	}
	return apiKey, nil
}

func getTerminalApiKey() (string, error) {
	apiKey := os.Getenv("TERMINAL_BEARER_TOKEN")
	if apiKey == "" {
		return "", errors.New("invalid api key")
	}
	return apiKey, nil
}
