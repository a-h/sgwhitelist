package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func handler(request interface{}) error {
	urlsEnv := strings.Split(os.Getenv("URLS"), ",")
	if len(urlsEnv) == 0 {
		return errors.New("whitelist lambda: no urls to configure")
	}
	urls := make([]*url.URL, len(urlsEnv))
	for i, ue := range urlsEnv {
		u, err := url.Parse(ue)
		if err != nil {
			return fmt.Errorf("whitelist lambda: invalid URL: %v", ue)
		}
		urls[i] = u
	}

	sgs := strings.Split(os.Getenv("SECURITY_GROUPS"), ",")
	if len(sgs) == 0 {
		return errors.New("whitelist lambda: no security groups to configure")
	}

	// Look up IP addresses of allowed domains.
	urlToAddresses := make(map[*url.URL][]string)
	var errs []error
	for _, u := range urls {
		addrs, err := net.LookupHost(u.Host)
		if err != nil {
			errs = append(errs, err)
		}
		urlToAddresses[u] = append(urlToAddresses[u], addrs...)
	}
	if err := joinErrs(errs); err != nil {
		return err
	}

	// Provide egress to the IP addresses to each of the security groups.
	for _, sg := range sgs {
		for u, addrs := range urlToAddresses {
			for _, addr := range addrs {
				p := port(u)
				err := authorizeAccessTo(sg, addr, p)
				if err != nil {
					errs = append(errs, err)
				}
				log(u, sg, addr, p)
			}
		}
	}
	if err := joinErrs(errs); err != nil {
		return err
	}

	return nil
}

func log(u *url.URL, sg, addr string, port int64) {
	le := map[string]interface{}{
		"time": time.Now().UTC(),
		"url":  u.String(),
		"sg":   sg,
		"addr": addr,
		"port": port,
	}
	e, _ := json.Marshal(le)
	fmt.Println(string(e))
}

func port(u *url.URL) int64 {
	ps := u.Port()
	if p, err := strconv.ParseInt(ps, 10, 64); err == nil {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return 80
	}
	return 443
}

func authorizeAccessTo(securityGroup string, ipAddress string, port int64) error {
	sess := session.New()
	client := ec2.New(sess)
	input := &ec2.AuthorizeSecurityGroupEgressInput{}
	input.SetGroupId(securityGroup)
	input.SetIpProtocol("tcp")
	input.SetFromPort(port)
	input.SetToPort(port)
	input.SetCidrIp(ipAddress + "/32")
	_, err := client.AuthorizeSecurityGroupEgress(input)
	if err != nil {
		return fmt.Errorf("whitelist lambda: failed to set security group info: %v", err)
	}
	return err
}

func joinErrs(errs []error) error {
	if errs == nil || len(errs) == 0 {
		return nil
	}
	s := make([]string, len(errs))
	for i, err := range errs {
		s[i] = err.Error()
	}
	return fmt.Errorf("whitelist lambda: [ %v ]", strings.Join(s, ", "))
}

func main() {
	lambda.Start(handler)
}
