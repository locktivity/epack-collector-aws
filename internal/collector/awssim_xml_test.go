package collector

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
)

// IAM, STS, S3, S3 Control, EC2, RDS, ELB, Auto Scaling, SNS and CloudFront
// answer in XML, which the kit's shape check can't read. The simulator works
// on those answers in a JSON form instead, and the recording's are read into
// it too, so the check compares XML answers as it does JSON ones. Collect
// writes the JSON form back as XML before the collector sees it.
//
// In the JSON form, the root element is the one field of an object. An
// element with attributes or child elements is an object: each attribute
// under @ and its name, each child under its name as a list, so an element
// with one child and one with several have the same shape, and any text
// under #text. Any other element is its text. A field the simulator sets
// to a value that isn't a list goes in a list when the body is written, so
// it can set a recorded item's fields as plain values.

// simXMLDecode reads an XML body into the JSON form.
func simXMLDecode(body string) (map[string]any, error) {
	type node struct {
		name     string
		attrs    []xml.Attr
		children []*node
		text     strings.Builder
	}
	d := xml.NewDecoder(strings.NewReader(body))
	var stack []*node
	var root *node
	for {
		tok, err := d.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			n := &node{name: simQName(tok.Name), attrs: slices.Clone(tok.Attr)}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(tok)
			}
		}
	}
	if root == nil {
		return nil, errors.New("no root element")
	}
	var value func(n *node) any
	value = func(n *node) any {
		if len(n.attrs) == 0 && len(n.children) == 0 {
			return n.text.String()
		}
		obj := map[string]any{}
		for _, a := range n.attrs {
			obj["@"+simQName(a.Name)] = a.Value
		}
		for _, c := range n.children {
			list, _ := obj[c.name].([]any)
			obj[c.name] = append(list, value(c))
		}
		if text := n.text.String(); strings.TrimSpace(text) != "" {
			obj["#text"] = text
		}
		return obj
	}
	return map[string]any{root.name: value(root)}, nil
}

func simQName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

// simXMLForm puts each child value of the JSON form that isn't a list in
// one, so a body the simulator built keeps the recording's shape.
func simXMLForm(doc map[string]any) map[string]any {
	out := map[string]any{}
	for name, v := range doc {
		out[name] = simXMLValue(v)
	}
	return out
}

func simXMLValue(v any) any {
	obj, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(obj))
	for k, child := range obj {
		switch {
		case strings.HasPrefix(k, "@"), k == "#text":
			out[k] = child
		default:
			list, isList := child.([]any)
			if !isList {
				list = []any{child}
			}
			items := make([]any, 0, len(list))
			for _, item := range list {
				items = append(items, simXMLValue(item))
			}
			out[k] = items
		}
	}
	return out
}

// simXMLEncode writes the JSON form as XML. Children go in name order,
// which the AWS SDK's decoders don't depend on.
func simXMLEncode(doc map[string]any) (string, error) {
	if len(doc) != 1 {
		return "", fmt.Errorf("the JSON form of an XML body has %d root elements", len(doc))
	}
	var b strings.Builder
	for name, v := range doc {
		if err := simXMLWrite(&b, name, v); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func simXMLWrite(b *strings.Builder, name string, v any) error {
	switch v := v.(type) {
	case []any:
		for _, item := range v {
			if err := simXMLWrite(b, name, item); err != nil {
				return err
			}
		}
		return nil
	case nil:
		return nil
	case string:
		b.WriteString("<" + name + ">")
		if err := xml.EscapeText(b, []byte(v)); err != nil {
			return err
		}
		b.WriteString("</" + name + ">")
		return nil
	case bool, float64, int:
		return simXMLWrite(b, name, fmt.Sprint(v))
	case map[string]any:
		b.WriteString("<" + name)
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if !strings.HasPrefix(k, "@") {
				continue
			}
			s, ok := v[k].(string)
			if !ok {
				return fmt.Errorf("%s: attribute %s is not a string", name, k)
			}
			b.WriteString(" " + strings.TrimPrefix(k, "@") + `="`)
			if err := xml.EscapeText(b, []byte(s)); err != nil {
				return err
			}
			b.WriteString(`"`)
		}
		b.WriteString(">")
		if text, ok := v["#text"].(string); ok {
			if err := xml.EscapeText(b, []byte(text)); err != nil {
				return err
			}
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if strings.HasPrefix(k, "@") || k == "#text" {
				continue
			}
			if err := simXMLWrite(b, k, v[k]); err != nil {
				return err
			}
		}
		b.WriteString("</" + name + ">")
		return nil
	}
	return fmt.Errorf("%s: %T has no XML form", name, v)
}

// simXMLBody encodes doc, a body in the JSON form, for a response.
func simXMLBody(doc map[string]any) string {
	raw, err := json.Marshal(simXMLForm(doc))
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// The JSON form must give the AWS SDK what the XML did, so a recorded body
// read into it and written back has to decode the same.
func TestSimXMLRoundTrip(t *testing.T) {
	for _, body := range []string{
		`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`,
		`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-west-2</LocationConstraint>`,
		`<DescribeVolumesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId><volumeSet/></DescribeVolumesResponse>`,
		"<ListMFADevicesResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">\n  <ListMFADevicesResult>\n    <MFADevices>\n      <member><UserName>a &amp; b</UserName></member>\n      <member><UserName>c</UserName></member>\n    </MFADevices>\n  </ListMFADevicesResult>\n</ListMFADevicesResponse>",
		`<AccessControlPolicy><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee></Grant></AccessControlList></AccessControlPolicy>`,
	} {
		doc, err := simXMLDecode(body)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		written, err := simXMLEncode(doc)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		again, err := simXMLDecode(written)
		if err != nil {
			t.Fatalf("%s: %v", written, err)
		}
		if a, b := simJSON(doc), simJSON(again); a != b {
			t.Errorf("%s\nreads as %s\nand written back as %s, which reads as %s", body, a, written, b)
		}
	}
	doc, err := simXMLDecode(`<R><Items><member><Name>x</Name></member></Items><Empty/></R>`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := simJSON(doc), `{"R":{"Empty":[""],"Items":[{"member":[{"Name":["x"]}]}]}}`; got != want {
		t.Errorf("JSON form %s, want %s", got, want)
	}
	if got, want := simXMLBody(map[string]any{"R": map[string]any{"Name": "x", "Items": map[string]any{"member": []any{"a", "b"}}}}),
		`{"R":{"Items":[{"member":["a","b"]}],"Name":["x"]}}`; got != want {
		t.Errorf("built body %s, want %s", got, want)
	}
}

func simJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
