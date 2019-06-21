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

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go/aws"

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
	portToIPAccess := make(portToIPAccess)
	for u, addrs := range urlToAddresses {
		p := port(u)
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil {
				portToIPAccess[p] = append(portToIPAccess[p], ipAccess{
					ip: ip,
					u:  u,
				})
			}
		}
	}
	for _, sg := range sgs {
		for p, to := range portToIPAccess {
			err := authorizeAccessTo(sg, p, to)
			if err != nil {
				log(sg, p, to, err)
				errs = append(errs, err)
				continue
			}
			log(sg, p, to, nil)
		}
	}
	if err := joinErrs(errs); err != nil {
		return err
	}

	return nil
}

func log(sg string, port int64, to []ipAccess, err error) {
	for _, ipa := range to {
		le := struct {
			Time  time.Time `json:"time"`
			SG    string    `json:"sg"`
			URL   string    `json:"url"`
			Addr  string    `json:"addr"`
			Port  int64     `json:"port"`
			Err   string    `json:"err"`
			Level string    `json:"level"`
		}{
			Time:  time.Now().UTC(),
			SG:    sg,
			URL:   ipa.u.String(),
			Addr:  ipa.ip.String(),
			Port:  port,
			Level: "INFO",
		}
		if err != nil {
			le.Level = "ERROR"
			le.Err = err.Error()
		}
		e, _ := json.Marshal(le)
		fmt.Println(string(e))
	}
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

type portToIPAccess map[int64][]ipAccess

type ipAccess struct {
	// IP address to access.
	ip net.IP
	// Target URL, used for the description.
	u *url.URL
}

func (a ipAccess) String() string {
	return fmt.Sprintf("{ IP: %v, URL: %v}", a.ip.String(), a.u.String())
}

func authorizeAccessTo(securityGroup string, port int64, to []ipAccess) error {
	sess := session.New()
	client := ec2.New(sess)
	perm := &ec2.IpPermission{}
	perm.SetIpProtocol("tcp")
	perm.SetFromPort(port)
	perm.SetToPort(port)

	ipRanges := []*ec2.IpRange{}
	ipV6Ranges := []*ec2.Ipv6Range{}
	for _, ipa := range to {
		if ipa.ip.To4() != nil {
			ipRanges = append(ipRanges, &ec2.IpRange{
				CidrIp:      aws.String(ipa.ip.String() + "/32"),
				Description: aws.String(ipa.u.String()),
			})
			// It's not IP v6.
			continue
		}
		ipV6Ranges = append(ipV6Ranges, &ec2.Ipv6Range{
			CidrIpv6:    aws.String(ipa.ip.String() + "/128"),
			Description: aws.String(ipa.u.String()),
		})
	}
	perm.SetIpRanges(ipRanges)
	perm.SetIpv6Ranges(ipV6Ranges)

	input := &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId:       aws.String(securityGroup),
		IpPermissions: []*ec2.IpPermission{perm},
	}
	_, err := client.AuthorizeSecurityGroupEgress(input)
	if err != nil {
		if awserr, isAWSErr := err.(awserr.Error); isAWSErr && awserr.Code() == "InvalidPermission.Duplicate" {
			return nil
		}
		return fmt.Errorf("whitelist lambda: failed to set security group info for %v string on port %d to %v: %v", securityGroup, port, to, err)
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
