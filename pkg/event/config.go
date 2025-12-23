/*
 * MinIO Cloud Storage, (C) 2018 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package event

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/minio/minio-go/v7/pkg/set"
)

// ValidateFilterRuleValue - checks if given value is filter rule value or not.
func ValidateFilterRuleValue(value string) error {
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return &ErrInvalidFilterValue{value}
		}
	}

	if len(value) <= 1024 && utf8.ValidString(value) && !strings.Contains(value, `\`) {
		return nil
	}

	return &ErrInvalidFilterValue{value}
}

// FilterRule - represents elements inside <FilterRule>...</FilterRule>
type FilterRule struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

func (filter FilterRule) isEmpty() bool {
	return filter.Name == "" && filter.Value == ""
}

// MarshalXML implements a custom marshaller to support `omitempty` feature.
func (filter FilterRule) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if filter.isEmpty() {
		return nil
	}
	type filterRuleWrapper FilterRule
	return e.EncodeElement(filterRuleWrapper(filter), start)
}

// UnmarshalXML - decodes XML data.
func (filter *FilterRule) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Make subtype to avoid recursive UnmarshalXML().
	type filterRule FilterRule
	rule := filterRule{}
	if err := d.DecodeElement(&rule, &start); err != nil {
		return err
	}

	if rule.Name != "prefix" && rule.Name != "suffix" {
		return &ErrInvalidFilterName{rule.Name}
	}

	if err := ValidateFilterRuleValue(filter.Value); err != nil {
		return err
	}

	*filter = FilterRule(rule)

	return nil
}

// FilterRuleList - represents multiple <FilterRule>...</FilterRule>
type FilterRuleList struct {
	Rules []FilterRule `xml:"FilterRule,omitempty"`
}

// UnmarshalXML - decodes XML data.
func (ruleList *FilterRuleList) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Make subtype to avoid recursive UnmarshalXML().
	type filterRuleList FilterRuleList
	rules := filterRuleList{}
	if err := d.DecodeElement(&rules, &start); err != nil {
		return err
	}

	// FilterRuleList must have only one prefix and/or suffix.
	nameSet := set.NewStringSet()
	for _, rule := range rules.Rules {
		if nameSet.Contains(rule.Name) {
			if rule.Name == "prefix" {
				return &ErrFilterNamePrefix{}
			}

			return &ErrFilterNameSuffix{}
		}

		nameSet.Add(rule.Name)
	}

	*ruleList = FilterRuleList(rules)
	return nil
}

func (ruleList FilterRuleList) isEmpty() bool {
	return len(ruleList.Rules) == 0
}

// Pattern - returns pattern using prefix and suffix values.
func (ruleList FilterRuleList) Pattern() string {
	var prefix string
	var suffix string

	for _, rule := range ruleList.Rules {
		switch rule.Name {
		case "prefix":
			prefix = rule.Value
		case "suffix":
			suffix = rule.Value
		}
	}

	return NewPattern(prefix, suffix)
}

// S3Key - represents elements inside <S3Key>...</S3Key>
type S3Key struct {
	RuleList FilterRuleList `xml:"S3Key,omitempty" json:"S3Key,omitempty"`
}

// MarshalXML implements a custom marshaller to support `omitempty` feature.
func (s3Key S3Key) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if s3Key.RuleList.isEmpty() {
		return nil
	}
	type s3KeyWrapper S3Key
	return e.EncodeElement(s3KeyWrapper(s3Key), start)
}

// common - represents common elements inside <QueueConfiguration>, <CloudFunctionConfiguration>
// and <TopicConfiguration>
type common struct {
	ID     string `xml:"Id" json:"Id"`
	Filter S3Key  `xml:"Filter" json:"Filter"`
	Events []Name `xml:"Event" json:"Event"`
}

// Queue - represents elements inside <QueueConfiguration>
type Queue struct {
	common
	ARN ARN `xml:"Queue"`
}

// UnmarshalXML - decodes XML data.
func (q *Queue) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Make subtype to avoid recursive UnmarshalXML().
	type queue Queue
	parsedQueue := queue{}
	if err := d.DecodeElement(&parsedQueue, &start); err != nil {
		return err
	}

	if len(parsedQueue.Events) == 0 {
		return errors.New("missing event name(s)")
	}

	eventStringSet := set.NewStringSet()
	for _, eventName := range parsedQueue.Events {
		if eventStringSet.Contains(eventName.String()) {
			return &ErrDuplicateEventName{eventName}
		}

		eventStringSet.Add(eventName.String())
	}

	*q = Queue(parsedQueue)

	return nil
}

// Validate - checks whether queue has valid values or not.
func (q Queue) Validate(region string, targetList *TargetList) error {
	if q.ARN.Region == "" {
		if !targetList.Exists(q.ARN.TargetID) {
			return &ErrARNNotFound{q.ARN}
		}
		return nil
	}

	if region != "" && q.ARN.Region != region {
		return &ErrUnknownRegion{q.ARN.Region}
	}

	if !targetList.Exists(q.ARN.TargetID) {
		return &ErrARNNotFound{q.ARN}
	}

	return nil
}

// SetRegion - sets region value to queue's ARN.
func (q *Queue) SetRegion(region string) {
	q.ARN.Region = region
}

// ToRulesMap - converts Queue to RulesMap
func (q Queue) ToRulesMap() RulesMap {
	pattern := q.Filter.RuleList.Pattern()
	return NewRulesMap(q.Events, pattern, q.ARN.TargetID)
}

// Unused.  Available for completion.
type lambda struct {
	ARN string `xml:"CloudFunction"`
}

// Topic - represents elements inside <TopicConfiguration>
// Exported for use with Google Pub/Sub and similar topic-based notification systems.
type Topic struct {
	common
	ARN ARN `xml:"Topic" json:"Topic"`
}

// Validate - checks whether Topic fields are valid or not.
func (t Topic) Validate(region string, targetList *TargetList) error {
	if t.ARN.Region == "" {
		if !targetList.Exists(t.ARN.TargetID) {
			return &ErrARNNotFound{t.ARN}
		}
		return nil
	}

	if region != "" && t.ARN.Region != region {
		return &ErrUnknownRegion{t.ARN.Region}
	}

	if !targetList.Exists(t.ARN.TargetID) {
		return &ErrARNNotFound{t.ARN}
	}

	return nil
}

// SetRegion - sets region value to topic's ARN.
func (t *Topic) SetRegion(region string) {
	t.ARN.Region = region
}

// ToRulesMap - converts Topic to RulesMap
func (t Topic) ToRulesMap() RulesMap {
	pattern := t.Filter.RuleList.Pattern()
	return NewRulesMap(t.Events, pattern, t.ARN.TargetID)
}

// slicesEqualAsSet checks if two slices contain the same unique elements (order and duplicates ignored).
func slicesEqualAsSet[T comparable](s1, s2 []T) bool {
	// Create sets from both slices
	set1 := make(map[T]struct{}, len(s1))
	for _, e := range s1 {
		set1[e] = struct{}{}
	}

	set2 := make(map[T]struct{}, len(s2))
	for _, e := range s2 {
		set2[e] = struct{}{}
	}

	// Check if sets have the same size
	if len(set1) != len(set2) {
		return false
	}

	// Check if all elements in set1 exist in set2
	for e := range set1 {
		if _, exists := set2[e]; !exists {
			return false
		}
	}

	return true
}

// queuesEqual checks if two queues are equal, considering events and filter rules as sets (order doesn't matter).
func queuesEqual(q1, q2 Queue) bool {
	// Compare ID and ARN
	if q1.ID != q2.ID {
		return false
	}
	if q1.ARN != q2.ARN {
		return false
	}
	// Compare filters (order-independent for filter rules)
	if !slicesEqualAsSet(q1.Filter.RuleList.Rules, q2.Filter.RuleList.Rules) {
		return false
	}
	// Compare events as sets (order doesn't matter)
	return slicesEqualAsSet(q1.Events, q2.Events)
}

// topicsEqual checks if two topics are equal, considering events and filter rules as sets (order doesn't matter).
func topicsEqual(t1, t2 Topic) bool {
	// Compare ID and ARN
	if t1.ID != t2.ID {
		return false
	}
	if t1.ARN != t2.ARN {
		return false
	}
	// Compare filters (order-independent for filter rules)
	if !slicesEqualAsSet(t1.Filter.RuleList.Rules, t2.Filter.RuleList.Rules) {
		return false
	}
	// Compare events as sets (order doesn't matter)
	return slicesEqualAsSet(t1.Events, t2.Events)
}

// Config - notification configuration described in
// http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html
type Config struct {
	XMLNS      string   `xml:"xmlns,attr,omitempty"`
	XMLName    xml.Name `xml:"NotificationConfiguration"`
	QueueList  []Queue  `xml:"QueueConfiguration,omitempty"`
	LambdaList []lambda `xml:"CloudFunctionConfiguration,omitempty"`
	TopicList  []Topic  `xml:"TopicConfiguration,omitempty"`
}

// UnmarshalXML - decodes XML data.
func (conf *Config) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Make subtype to avoid recursive UnmarshalXML().
	type config Config
	parsedConfig := config{}
	if err := d.DecodeElement(&parsedConfig, &start); err != nil {
		return err
	}

	// Empty queue list means user wants to delete the notification configuration.
	if len(parsedConfig.QueueList) > 0 {
		for i, q1 := range parsedConfig.QueueList[:len(parsedConfig.QueueList)-1] {
			for _, q2 := range parsedConfig.QueueList[i+1:] {
				// Removes the region from ARN if server region is not set
				if q2.ARN.Region != "" && q1.ARN.Region == "" {
					q2.ARN.Region = ""
				}
				if queuesEqual(q1, q2) {
					return &ErrDuplicateQueueConfiguration{q1}
				}
			}
		}
	}

	// Check for duplicate topic configurations
	if len(parsedConfig.TopicList) > 0 {
		for i, t1 := range parsedConfig.TopicList[:len(parsedConfig.TopicList)-1] {
			for _, t2 := range parsedConfig.TopicList[i+1:] {
				// Removes the region from ARN if server region is not set
				if t2.ARN.Region != "" && t1.ARN.Region == "" {
					t2.ARN.Region = ""
				}
				if topicsEqual(t1, t2) {
					return &ErrDuplicateTopicConfiguration{t1}
				}
			}
		}
	}

	// Lambda functions are not supported
	if len(parsedConfig.LambdaList) > 0 {
		return &ErrUnsupportedConfiguration{}
	}

	*conf = Config(parsedConfig)

	return nil
}

// Validate - checks whether config has valid values or not.
func (conf Config) Validate(region string, targetList *TargetList) error {
	for _, queue := range conf.QueueList {
		if err := queue.Validate(region, targetList); err != nil {
			return err
		}
	}

	for _, topic := range conf.TopicList {
		if err := topic.Validate(region, targetList); err != nil {
			return err
		}
	}

	return nil
}

// SetRegion - sets region to all queue and topic configurations.
func (conf *Config) SetRegion(region string) {
	for i := range conf.QueueList {
		conf.QueueList[i].SetRegion(region)
	}

	for i := range conf.TopicList {
		conf.TopicList[i].SetRegion(region)
	}
}

// ToRulesMap - converts all queue and topic configurations to RulesMap.
func (conf *Config) ToRulesMap() RulesMap {
	rulesMap := make(RulesMap)

	for _, queue := range conf.QueueList {
		rulesMap.Add(queue.ToRulesMap())
	}

	for _, topic := range conf.TopicList {
		rulesMap.Add(topic.ToRulesMap())
	}

	return rulesMap
}

// ParseConfig - parses data in reader to notification configuration.
func ParseConfig(reader io.Reader, region string, targetList *TargetList) (*Config, error) {
	var config Config

	if err := xml.NewDecoder(reader).Decode(&config); err != nil {
		return nil, err
	}

	if err := config.Validate(region, targetList); err != nil {
		return nil, err
	}

	config.SetRegion(region)
	//If xml namespace is empty, set a default value before returning.
	if config.XMLNS == "" {
		config.XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"
	}
	return &config, nil
}
