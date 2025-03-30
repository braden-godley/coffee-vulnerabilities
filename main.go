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
	"time"

	"github.com/samber/lo"
    godotenv "github.com/joho/godotenv"
	openai "github.com/sashabaranov/go-openai"
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

func main() {
	log.SetPrefix("coffee: ")
	log.SetFlags(0)

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
		if desc, ok := lo.Find(v.Cve.Descriptions, func(desc Description) bool {
			return desc.Lang == "en"
		}); ok {
			log.Printf("Description: %s", desc.Value)
		}
		v.getCompaniesAffected()
		log.Println("")
	}

	log.Printf("Found %d/%d CVEs with score at least %f", len(critical), len(vulns.Vulnerabilities), ScoreThreshold)
}

func getVulnerabilities() (*CVEResponse, error) {
	end := time.Now()
	start := end.Add(-24 * time.Hour)

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

func (v Vulnerability) getCompaniesAffected() ([]string, error) {
	client := openai.NewClient("")

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
            <company name="Facebook" address="1 Hacker Way" addressLineTwo="" city="Menlo Park" state="CA" zip="94025"></company>
        </response>

        Here is the vulnerability description: %s
    `, desc)

	resp, err := client.CreateChatCompletion(
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

	log.Println("Response")
	log.Println(resp.Choices[0].Message.Content)

	return []string{}, nil
}

func getApiKey() string, error {
    
}
