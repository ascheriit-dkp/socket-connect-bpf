// Copyright 2026 Ascheriit-Dkp.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxArgumentRedactionPatterns = 64
	maxArgumentRedactionPatternLength = 1024
	argumentRedactionReplacement = "[REDACTED]"
)

type argumentRedactionPatternValues []string

func (values *argumentRedactionPatternValues) String() string {
	if values == nil {
		return ""
	}

	return strings.Join(*values, ",")
}

func (values *argumentRedactionPatternValues) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type argumentRedactor struct {
	patterns []*regexp.Regexp
}

var activeArgumentRedactor = &argumentRedactor{}

func registerArgumentRedactionFlags(
	flagSet *flag.FlagSet,
) *argumentRedactionPatternValues {
	values := &argumentRedactionPatternValues{}
	flagSet.Var(
		values,
		"redact-arg",
		"replace process-argument text matching REGEX with [REDACTED]; may be repeated",
	)
	return values
}

func configureArgumentRedaction(patterns []string) error {
	redactor, err := newArgumentRedactor(patterns)
	if err != nil {
		return err
	}

	activeArgumentRedactor = redactor
	return nil
}

func newArgumentRedactor(patterns []string) (*argumentRedactor, error) {
	if len(patterns) > maxArgumentRedactionPatterns {
		return nil, fmt.Errorf(
			"too many --redact-arg patterns: got %d, maximum is %d",
			len(patterns),
			maxArgumentRedactionPatterns,
		)
	}

	redactor := &argumentRedactor{
		patterns: make([]*regexp.Regexp, 0, len(patterns)),
	}

	for index, pattern := range patterns {
		if pattern == "" {
			return nil, fmt.Errorf(
				"--redact-arg pattern %d must not be empty",
				index+1,
			)
		}
		if len(pattern) > maxArgumentRedactionPatternLength {
			return nil, fmt.Errorf(
				"--redact-arg pattern %d exceeds %d bytes",
				index+1,
				maxArgumentRedactionPatternLength,
			)
		}

		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf(
				"compile --redact-arg pattern %d %q: %w",
				index+1,
				pattern,
				err,
			)
		}
		if compiled.MatchString("") {
			return nil, fmt.Errorf(
				"--redact-arg pattern %d %q matches empty text",
				index+1,
				pattern,
			)
		}

		redactor.patterns = append(redactor.patterns, compiled)
	}

	return redactor, nil
}

func (redactor *argumentRedactor) Redact(value string) string {
	if redactor == nil || value == "" {
		return value
	}

	redacted := value
	for _, pattern := range redactor.patterns {
		redacted = pattern.ReplaceAllString(
			redacted,
			argumentRedactionReplacement,
		)
	}

	return redacted
}

func redactProcessArguments(value string) string {
	return activeArgumentRedactor.Redact(value)
}
