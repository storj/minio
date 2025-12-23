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

func TestQueueUnmarshalXML(t *testing.T) {
	dataCase1 := []byte(`
<QueueConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</QueueConfiguration>`)

	dataCase2 := []byte(`
<QueueConfiguration>
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
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectCreated:Put</Event>
</QueueConfiguration>`)

	dataCase3 := []byte(`
<QueueConfiguration>
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
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectCreated:Put</Event>
   <Event>s3:ObjectCreated:Put</Event>
</QueueConfiguration>`)

	testCases := []struct {
		data      []byte
		expectErr bool
	}{
		{dataCase1, false},
		{dataCase2, false},
		{dataCase3, true},
	}

	for i, testCase := range testCases {
		err := xml.Unmarshal(testCase.data, &Queue{})
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestQueueValidate(t *testing.T) {
	data := []byte(`
<QueueConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</QueueConfiguration>`)
	queue1 := &Queue{}
	if err := xml.Unmarshal(data, queue1); err != nil {
		panic(err)
	}

	data = []byte(`
<QueueConfiguration>
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
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectCreated:Put</Event>
</QueueConfiguration>`)
	queue2 := &Queue{}
	if err := xml.Unmarshal(data, queue2); err != nil {
		panic(err)
	}

	data = []byte(`
<QueueConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Queue>arn:minio:sqs:eu-west-2:1:webhook</Queue>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</QueueConfiguration>`)
	queue3 := &Queue{}
	if err := xml.Unmarshal(data, queue3); err != nil {
		panic(err)
	}

	targetList1 := NewTargetList()

	targetList2 := NewTargetList()
	if err := targetList2.Add(&ExampleTarget{TargetID{"1", "webhook"}, false, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		queue      *Queue
		region     string
		targetList *TargetList
		expectErr  bool
	}{
		{queue1, "eu-west-1", nil, true},
		{queue2, "us-east-1", targetList1, true},
		{queue3, "", targetList2, false},
		{queue2, "us-east-1", targetList2, false},
	}

	for i, testCase := range testCases {
		err := testCase.queue.Validate(testCase.region, testCase.targetList)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestQueueSetRegion(t *testing.T) {
	data := []byte(`
<QueueConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</QueueConfiguration>`)
	queue1 := &Queue{}
	if err := xml.Unmarshal(data, queue1); err != nil {
		panic(err)
	}

	data = []byte(`
<QueueConfiguration>
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
   <Queue>arn:minio:sqs::1:webhook</Queue>
   <Event>s3:ObjectCreated:Put</Event>
</QueueConfiguration>`)
	queue2 := &Queue{}
	if err := xml.Unmarshal(data, queue2); err != nil {
		panic(err)
	}

	testCases := []struct {
		queue          *Queue
		region         string
		expectedResult ARN
	}{
		{queue1, "eu-west-1", ARN{TargetID: TargetID{"1", "webhook"}, Region: "eu-west-1", ServiceType: "sqs"}},
		{queue1, "", ARN{TargetID: TargetID{"1", "webhook"}, Region: "", ServiceType: "sqs"}},
		{queue2, "us-east-1", ARN{TargetID: TargetID{"1", "webhook"}, Region: "us-east-1", ServiceType: "sqs"}},
		{queue2, "", ARN{TargetID: TargetID{"1", "webhook"}, Region: "", ServiceType: "sqs"}},
	}

	for i, testCase := range testCases {
		testCase.queue.SetRegion(testCase.region)
		result := testCase.queue.ARN

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestQueueToRulesMap(t *testing.T) {
	data := []byte(`
<QueueConfiguration>
   <Id>1</Id>
   <Filter></Filter>
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectAccessed:*</Event>
   <Event>s3:ObjectCreated:*</Event>
   <Event>s3:ObjectRemoved:*</Event>
</QueueConfiguration>`)
	queueCase1 := &Queue{}
	if err := xml.Unmarshal(data, queueCase1); err != nil {
		panic(err)
	}

	data = []byte(`
<QueueConfiguration>
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
   <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
   <Event>s3:ObjectCreated:Put</Event>
</QueueConfiguration>`)
	queueCase2 := &Queue{}
	if err := xml.Unmarshal(data, queueCase2); err != nil {
		panic(err)
	}

	rulesMapCase1 := NewRulesMap([]Name{ObjectAccessedAll, ObjectCreatedAll, ObjectRemovedAll}, "*", TargetID{"1", "webhook"})
	rulesMapCase2 := NewRulesMap([]Name{ObjectCreatedPut}, "images/*jpg", TargetID{"1", "webhook"})

	testCases := []struct {
		queue          *Queue
		expectedResult RulesMap
	}{
		{queueCase1, rulesMapCase1},
		{queueCase2, rulesMapCase2},
	}

	for i, testCase := range testCases {
		result := testCase.queue.ToRulesMap()

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestConfigUnmarshalXML(t *testing.T) {
	dataCase1 := []byte(`
<NotificationConfiguration   xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)

	dataCase2 := []byte(`
	<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	   <QueueConfiguration>
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
	      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
	      <Event>s3:ObjectCreated:Put</Event>
	   </QueueConfiguration>
	</NotificationConfiguration>
	`)

	dataCase3 := []byte(`
	<NotificationConfiguration>
	   <QueueConfiguration>
	      <Id>1</Id>
	      <Filter></Filter>
	      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
	      <Event>s3:ObjectAccessed:*</Event>
	      <Event>s3:ObjectCreated:*</Event>
	      <Event>s3:ObjectRemoved:*</Event>
	   </QueueConfiguration>
	   <QueueConfiguration>
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
	      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
	      <Event>s3:ObjectCreated:Put</Event>
	   </QueueConfiguration>
	</NotificationConfiguration>
	`)

	dataCase4 := []byte(`
	<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	   <QueueConfiguration>
	      <Id>1</Id>
	      <Filter></Filter>
	      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
	      <Event>s3:ObjectAccessed:*</Event>
	      <Event>s3:ObjectCreated:*</Event>
	      <Event>s3:ObjectRemoved:*</Event>
	   </QueueConfiguration>
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
	   <TopicConfiguration>
	      <Topic>arn:aws:sns:us-west-2:444455556666:sns-notification-one</Topic>
	      <Event>s3:ObjectCreated:*</Event>
	  </TopicConfiguration>
	</NotificationConfiguration>
	`)

	dataCase5 := []byte(`<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/" ></NotificationConfiguration>`)

	// Test case with only TopicConfiguration (should pass)
	dataCase6 := []byte(`
	<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	   <TopicConfiguration>
	      <Id>1</Id>
	      <Filter></Filter>
	      <Topic>arn:minio:sns:us-east-1:1:topic</Topic>
	      <Event>s3:ObjectCreated:*</Event>
	   </TopicConfiguration>
	</NotificationConfiguration>
	`)

	// Test case with both QueueConfiguration and TopicConfiguration (should pass)
	dataCase7 := []byte(`
	<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	   <QueueConfiguration>
	      <Id>1</Id>
	      <Filter></Filter>
	      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
	      <Event>s3:ObjectCreated:*</Event>
	   </QueueConfiguration>
	   <TopicConfiguration>
	      <Id>2</Id>
	      <Filter></Filter>
	      <Topic>arn:minio:sns:us-east-1:1:topic</Topic>
	      <Event>s3:ObjectRemoved:*</Event>
	   </TopicConfiguration>
	</NotificationConfiguration>
	`)

	// Test case with duplicate TopicConfiguration (should fail)
	dataCase8 := []byte(`
	<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
	   <TopicConfiguration>
	      <Id>1</Id>
	      <Filter></Filter>
	      <Topic>arn:minio:sns:us-east-1:1:topic</Topic>
	      <Event>s3:ObjectCreated:*</Event>
	   </TopicConfiguration>
	   <TopicConfiguration>
	      <Id>1</Id>
	      <Filter></Filter>
	      <Topic>arn:minio:sns:us-east-1:1:topic</Topic>
	      <Event>s3:ObjectCreated:*</Event>
	   </TopicConfiguration>
	</NotificationConfiguration>
	`)

	// Test case with duplicate TopicConfiguration with events in different order (should fail)
	dataCase9 := []byte(`
	<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
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
	      <Topic>arn:minio:sns:us-east-1:1:topic</Topic>
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
	      <Topic>arn:minio:sns:us-east-1:1:topic</Topic>
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
		{dataCase4, true}, // Still fails due to CloudFunctionConfiguration
		// make sure we don't fail when queue is empty.
		{dataCase5, false},
		{dataCase6, false}, // TopicConfiguration should now be accepted
		{dataCase7, false}, // Both Queue and Topic should be accepted
		{dataCase8, true},  // Duplicate TopicConfiguration should fail
		{dataCase9, true},  // Duplicate TopicConfiguration with filters and events in different order should fail
	}

	for i, testCase := range testCases {
		err := xml.Unmarshal(testCase.data, &Config{})
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	data := []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config1 := &Config{}
	if err := xml.Unmarshal(data, config1); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config2 := &Config{}
	if err := xml.Unmarshal(data, config2); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config3 := &Config{}
	if err := xml.Unmarshal(data, config3); err != nil {
		panic(err)
	}

	targetList1 := NewTargetList()

	targetList2 := NewTargetList()
	if err := targetList2.Add(&ExampleTarget{TargetID{"1", "webhook"}, false, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		config     *Config
		region     string
		targetList *TargetList
		expectErr  bool
	}{
		{config1, "eu-west-1", nil, true},
		{config2, "us-east-1", targetList1, true},
		{config3, "", targetList2, false},
		{config2, "us-east-1", targetList2, false},
	}

	for i, testCase := range testCases {
		err := testCase.config.Validate(testCase.region, testCase.targetList)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}

func TestConfigSetRegion(t *testing.T) {
	data := []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config1 := &Config{}
	if err := xml.Unmarshal(data, config1); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs::1:webhook</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config2 := &Config{}
	if err := xml.Unmarshal(data, config2); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs:us-east-1:2:amqp</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config3 := &Config{}
	if err := xml.Unmarshal(data, config3); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <TopicConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Topic>arn:minio:sns::1:topic</Topic>
      <Event>s3:ObjectCreated:*</Event>
   </TopicConfiguration>
</NotificationConfiguration>
`)
	config4 := &Config{}
	if err := xml.Unmarshal(data, config4); err != nil {
		panic(err)
	}

	testCases := []struct {
		config         *Config
		region         string
		expectedResult []ARN
	}{
		{config1, "eu-west-1", []ARN{{TargetID: TargetID{"1", "webhook"}, Region: "eu-west-1", ServiceType: "sqs"}}},
		{config1, "", []ARN{{TargetID: TargetID{"1", "webhook"}, Region: "", ServiceType: "sqs"}}},
		{config2, "us-east-1", []ARN{{TargetID: TargetID{"1", "webhook"}, Region: "us-east-1", ServiceType: "sqs"}}},
		{config2, "", []ARN{{TargetID: TargetID{"1", "webhook"}, Region: "", ServiceType: "sqs"}}},
		{config3, "us-east-1", []ARN{{TargetID: TargetID{"1", "webhook"}, Region: "us-east-1", ServiceType: "sqs"}, {TargetID: TargetID{"2", "amqp"}, Region: "us-east-1", ServiceType: "sqs"}}},
		{config3, "", []ARN{{TargetID: TargetID{"1", "webhook"}, Region: "", ServiceType: "sqs"}, {TargetID: TargetID{"2", "amqp"}, Region: "", ServiceType: "sqs"}}},
		{config4, "eu-west-1", []ARN{{TargetID: TargetID{"1", "topic"}, Region: "eu-west-1", ServiceType: "sns"}}},
		{config4, "", []ARN{{TargetID: TargetID{"1", "topic"}, Region: "", ServiceType: "sns"}}},
	}

	for i, testCase := range testCases {
		testCase.config.SetRegion(testCase.region)
		result := []ARN{}
		for _, queue := range testCase.config.QueueList {
			result = append(result, queue.ARN)
		}
		for _, topic := range testCase.config.TopicList {
			result = append(result, topic.ARN)
		}

		if !reflect.DeepEqual(result, testCase.expectedResult) {
			t.Fatalf("test %v: data: expected: %v, got: %v", i+1, testCase.expectedResult, result)
		}
	}
}

func TestConfigToRulesMap(t *testing.T) {
	data := []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config1 := &Config{}
	if err := xml.Unmarshal(data, config1); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs::1:webhook</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config2 := &Config{}
	if err := xml.Unmarshal(data, config2); err != nil {
		panic(err)
	}

	data = []byte(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs:us-east-1:2:amqp</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)
	config3 := &Config{}
	if err := xml.Unmarshal(data, config3); err != nil {
		panic(err)
	}

	rulesMapCase1 := NewRulesMap([]Name{ObjectAccessedAll, ObjectCreatedAll, ObjectRemovedAll}, "*", TargetID{"1", "webhook"})

	rulesMapCase2 := NewRulesMap([]Name{ObjectCreatedPut}, "images/*jpg", TargetID{"1", "webhook"})

	rulesMapCase3 := NewRulesMap([]Name{ObjectAccessedAll, ObjectCreatedAll, ObjectRemovedAll}, "*", TargetID{"1", "webhook"})
	rulesMapCase3.add([]Name{ObjectCreatedPut}, "images/*jpg", TargetID{"2", "amqp"})

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
	reader1 := strings.NewReader(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)

	reader2 := strings.NewReader(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)

	reader3 := strings.NewReader(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
   <QueueConfiguration>
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
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectCreated:Put</Event>
   </QueueConfiguration>
</NotificationConfiguration>
`)

	reader4 := strings.NewReader(`
<NotificationConfiguration  xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
   <QueueConfiguration>
      <Id>1</Id>
      <Filter></Filter>
      <Queue>arn:minio:sqs:us-east-1:1:webhook</Queue>
      <Event>s3:ObjectAccessed:*</Event>
      <Event>s3:ObjectCreated:*</Event>
      <Event>s3:ObjectRemoved:*</Event>
   </QueueConfiguration>
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
   <TopicConfiguration>
      <Topic>arn:aws:sns:us-west-2:444455556666:sns-notification-one</Topic>
      <Event>s3:ObjectCreated:*</Event>
  </TopicConfiguration>
</NotificationConfiguration>
`)

	targetList1 := NewTargetList()

	targetList2 := NewTargetList()
	if err := targetList2.Add(&ExampleTarget{TargetID{"1", "webhook"}, false, false}); err != nil {
		panic(err)
	}

	testCases := []struct {
		reader     *strings.Reader
		region     string
		targetList *TargetList
		expectErr  bool
	}{
		{reader1, "eu-west-1", nil, true},
		{reader2, "us-east-1", targetList1, true},
		{reader4, "us-east-1", targetList1, true},
		{reader3, "", targetList2, false},
		{reader2, "us-east-1", targetList2, false},
	}

	for i, testCase := range testCases {
		if _, err := testCase.reader.Seek(0, 0); err != nil {
			panic(err)
		}
		_, err := ParseConfig(testCase.reader, testCase.region, testCase.targetList)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("test %v: error: expected: %v, got: %v", i+1, testCase.expectErr, expectErr)
		}
	}
}
