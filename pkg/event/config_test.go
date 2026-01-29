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
	"reflect"
	"strings"
	"testing"
)

func TestValidateFilterRuleValue(t *testing.T) {
	testCases := []struct {
		value     string
		expectErr bool
	}{
		{"foo/.", true},
		{"../foo", true},
		{`foo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/bazfoo/bar/baz`, true},
		{string([]byte{0xff, 0xfe, 0xfd}), true},
		{`foo\bar`, true},
		{"Hello/世界", false},
	}

	for i, testCase := range testCases {
		err := ValidateFilterRuleValue(testCase.value)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestFilterRuleUnmarshalXML(t *testing.T) {
	testCases := []struct {
		data           []byte
		expectedResult *FilterRule
		expectErr      bool
	}{
		{[]byte(`<FilterRule></FilterRule>`), nil, true},
		{[]byte(`<FilterRule><Name></Name></FilterRule>`), nil, true},
		{[]byte(`<FilterRule><Value></Value></FilterRule>`), nil, true},
		{[]byte(`<FilterRule><Name></Name><Value></Value></FilterRule>`), nil, true},
		{[]byte(`<FilterRule><Name>Prefix</Name><Value>Hello/世界</Value></FilterRule>`), nil, true},
		{[]byte(`<FilterRule><Name>ends</Name><Value>foo/bar</Value></FilterRule>`), nil, true},
		{[]byte(`<FilterRule><Name>prefix</Name><Value>Hello/世界</Value></FilterRule>`), &FilterRule{"prefix", "Hello/世界"}, false},
		{[]byte(`<FilterRule><Name>suffix</Name><Value>foo/bar</Value></FilterRule>`), &FilterRule{"suffix", "foo/bar"}, false},
	}

	for i, testCase := range testCases {
		result := &FilterRule{}
		err := xml.Unmarshal(testCase.data, result)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestFilterRuleListUnmarshalXML(t *testing.T) {
	testCases := []struct {
		data           []byte
		expectedResult *FilterRuleList
		expectErr      bool
	}{
		{[]byte(`<S3Key><FilterRule><Name>suffix</Name><Value>Hello/世界</Value></FilterRule><FilterRule><Name>suffix</Name><Value>foo/bar</Value></FilterRule></S3Key>`), nil, true},
		{[]byte(`<S3Key><FilterRule><Name>prefix</Name><Value>Hello/世界</Value></FilterRule><FilterRule><Name>prefix</Name><Value>foo/bar</Value></FilterRule></S3Key>`), nil, true},
		{[]byte(`<S3Key><FilterRule><Name>prefix</Name><Value>Hello/世界</Value></FilterRule></S3Key>`), &FilterRuleList{[]FilterRule{{"prefix", "Hello/世界"}}}, false},
		{[]byte(`<S3Key><FilterRule><Name>suffix</Name><Value>foo/bar</Value></FilterRule></S3Key>`), &FilterRuleList{[]FilterRule{{"suffix", "foo/bar"}}}, false},
		{[]byte(`<S3Key><FilterRule><Name>prefix</Name><Value>Hello/世界</Value></FilterRule><FilterRule><Name>suffix</Name><Value>foo/bar</Value></FilterRule></S3Key>`), &FilterRuleList{[]FilterRule{{"prefix", "Hello/世界"}, {"suffix", "foo/bar"}}}, false},
	}

	for i, testCase := range testCases {
		result := &FilterRuleList{}
		err := xml.Unmarshal(testCase.data, result)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestFilterRuleListPattern(t *testing.T) {
	testCases := []struct {
		filterRuleList FilterRuleList
		expectedResult string
	}{
		{FilterRuleList{}, ""},
		{FilterRuleList{[]FilterRule{{"prefix", "Hello/世界"}}}, "Hello/世界*"},
		{FilterRuleList{[]FilterRule{{"suffix", "foo/bar"}}}, "*foo/bar"},
		{FilterRuleList{[]FilterRule{{"prefix", "Hello/世界"}, {"suffix", "foo/bar"}}}, "Hello/世界*foo/bar"},
	}

	for i, testCase := range testCases {
		result := testCase.filterRuleList.Pattern()

		if result != testCase.expectedResult {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestTopicUnmarshalXML(t *testing.T) {
	dataCase1 := []byte(`
<TopicConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</TopicConfiguration>`)

	dataCase2 := []byte(`
<TopicConfiguration>
   <Id>1</Id>
    <Filter>
        <S3Key>
            <FilterRule>
                <Name>prefix</Name>
                <Value>images/</Value>
            </FilterRule>
            <FilterRule>
                <Name>suffix</Name>
                <Value>jpg</Value>
            </FilterRule>
        </S3Key>
   </Filter>
   <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
   <Event>s3:ObjectCreated:Put</Event>
</TopicConfiguration>`)

	dataCase3 := []byte(`
<TopicConfiguration>
   <Id>1</Id>
    <Filter>
        <S3Key>
            <FilterRule>
                <Name>prefix</Name>
                <Value>images/</Value>
            </FilterRule>
            <FilterRule>
                <Name>suffix</Name>
                <Value>jpg</Value>
            </FilterRule>
        </S3Key>
   </Filter>
   <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
   <Event>s3:ObjectCreated:Put</Event>
   <Event>s3:ObjectCreated:Put</Event>
</TopicConfiguration>`)

	testCases := []struct {
		data      []byte
		expectErr bool
	}{
		{dataCase1, false},
		{dataCase2, false},
		{dataCase3, true}, // Duplicate events
	}

	for i, testCase := range testCases {
		topic := &Topic{}
		err := xml.Unmarshal(testCase.data, topic)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestTopicToRulesMap(t *testing.T) {
	data := []byte(`
<TopicConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</TopicConfiguration>`)
	topicCase1 := &Topic{}
	if err := xml.Unmarshal(data, topicCase1); err != nil {
		panic(err)
	}

	data = []byte(`
<TopicConfiguration>
   <Id>1</Id>
    <Filter>
        <S3Key>
            <FilterRule>
                <Name>prefix</Name>
                <Value>images/</Value>
            </FilterRule>
            <FilterRule>
                <Name>suffix</Name>
                <Value>jpg</Value>
            </FilterRule>
        </S3Key>
   </Filter>
   <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
   <Event>s3:ObjectCreated:Put</Event>
</TopicConfiguration>`)
	topicCase2 := &Topic{}
	if err := xml.Unmarshal(data, topicCase2); err != nil {
		panic(err)
	}

	rulesMapCase1 := NewRulesMap([]Name{ObjectAccessedAll, ObjectCreatedAll, ObjectRemovedAll}, "*", TargetID{"my-project", "my-topic"})
	rulesMapCase2 := NewRulesMap([]Name{ObjectCreatedPut}, "images/*jpg", TargetID{"my-project", "my-topic"})

	testCases := []struct {
		topic          *Topic
		expectedResult RulesMap
	}{
		{topicCase1, rulesMapCase1},
		{topicCase2, rulesMapCase2},
	}

	for i, testCase := range testCases {
		result := testCase.topic.ToRulesMap()

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestConfigUnmarshalXML(t *testing.T) {
	dataCase1 := []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	dataCase2 := []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
       <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:Put</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	dataCase3 := []byte(`
<NotificationConfiguration>
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
   <TopicConfiguration>
      <Id>2</Id>
       <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:another-topic</Topic>
      <Event>s3:ObjectCreated:Put</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	// Test case with CloudFunctionConfiguration (should fail - not supported)
	dataCase4 := []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessoryed:*</Event>
   </TopicConfiguration>
   <CloudFunctionConfiguration>
      <Id>1</Id>
      <Filter>
             <S3Key>
                 <FilterRule>
                     <Name>suffix</Name>
                     <Value>.jpg</Value>
                 </FilterRule>
             </S3Key>
      </Filter>
      <Cloudcode>arn:aws:lambda:us-west-2:444455556666:cloud-function-A</Cloudcode>
      <Event>s3:ObjectCreated:Put</Event>
   </CloudFunctionConfiguration>
</NotificationConfiguration>
`)

	dataCase5 := []byte(`<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></NotificationConfiguration>`)

	// Test case with duplicate TopicConfiguration (should fail)
	dataCase6 := []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:*</Event>
   </TopicConfiguration>
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:*</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	// Test case with duplicate TopicConfiguration with events in different order (should fail)
	dataCase7 := []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
   <TopicConfiguration>
      <Id>1</Id>
      <Filter>
           <S3Key>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectRemoved:*</Event>
      <Event>s3:ObjectCreated:*</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	testCases := []struct {
		data      []byte
		expectErr bool
	}{
		{dataCase1, false},
		{dataCase2, false},
		{dataCase3, false},
		{dataCase4, true}, // CloudFunctionConfiguration not supported
		{dataCase5, false}, // Empty config is valid
		{dataCase6, true},  // Duplicate TopicConfiguration should fail
		{dataCase7, true},  // Duplicate TopicConfiguration with filters and events in different order should fail
	}

	for i, testCase := range testCases {
		err := xml.Unmarshal(testCase.data, &Config{})
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestConfigToRulesMap(t *testing.T) {
	data := []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)
	config1 := &Config{}
	if err := xml.Unmarshal(data, config1); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
       <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:Put</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)
	config2 := &Config{}
	if err := xml.Unmarshal(data, config2); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
   <TopicConfiguration>
      <Id>2</Id>
       <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:another-topic</Topic>
      <Event>s3:ObjectCreated:Put</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)
	config3 := &Config{}
	if err := xml.Unmarshal(data, config3); err != nil {
		panic(err)
	}

	rulesMapCase1 := NewRulesMap([]Name{ObjectAccessedAll, ObjectCreatedAll, ObjectRemovedAll}, "*", TargetID{"my-project", "my-topic"})

	rulesMapCase2 := NewRulesMap([]Name{ObjectCreatedPut}, "images/*jpg", TargetID{"my-project", "my-topic"})

	rulesMapCase3 := NewRulesMap([]Name{ObjectAccessedAll, ObjectCreatedAll, ObjectRemovedAll}, "*", TargetID{"my-project", "my-topic"})
	rulesMapCase3.add([]Name{ObjectCreatedPut}, "images/*jpg", TargetID{"my-project", "another-topic"})

	testCases := []struct {
		config         *Config
		expectedResult RulesMap
	}{
		{config1, rulesMapCase1},
		{config2, rulesMapCase2},
		{config3, rulesMapCase3},
	}

	for i, testCase := range testCases {
		result := testCase.config.ToRulesMap()

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestParseConfig(t *testing.T) {
	// Valid single topic config
	reader1 := strings.NewReader(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	// Valid topic config with filters
	reader2 := strings.NewReader(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
       <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:Put</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	// Valid multiple topic configs
	reader3 := strings.NewReader(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </TopicConfiguration>
   <TopicConfiguration>
      <Id>2</Id>
       <Filter>
           <S3Key>
               <FilterRule>
                   <Name>prefix</Name>
                   <Value>images/</Value>
               </FilterRule>
               <FilterRule>
                   <Name>suffix</Name>
                   <Value>jpg</Value>
               </FilterRule>
           </S3Key>
      </Filter>
      <Topic>arn:gcp:pubsub::my-project:another-topic</Topic>
      <Event>s3:ObjectCreated:Put</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)

	// Config with CloudFunctionConfiguration (should fail)
	reader4 := strings.NewReader(`
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:gcp:pubsub::my-project:my-topic</Topic>
      <Event>s3:ObjectCreated:*</Event>
   </TopicConfiguration>
   <CloudFunctionConfiguration>
      <Id>1</Id>
      <Filter>
             <S3Key>
                 <FilterRule>
                     <Name>suffix</Name>
                     <Value>.jpg</Value>
                 </FilterRule>
             </S3Key>
      </Filter>
      <Cloudcode>arn:aws:lambda:us-west-2:444455556666:cloud-function-A</Cloudcode>
      <Event>s3:ObjectCreated:Put</Event>
   </CloudFunctionConfiguration>
</NotificationConfiguration>
`)

	testCases := []struct {
		reader    *strings.Reader
		expectErr bool
	}{
		{reader1, false},
		{reader2, false},
		{reader3, false},
		{reader4, true}, // CloudFunctionConfiguration not supported
	}

	for i, testCase := range testCases {
		if _, err := testCase.reader.Seek(0, 0); err != nil {
			panic(err)
		}
		_, err := ParseConfig(testCase.reader)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}
