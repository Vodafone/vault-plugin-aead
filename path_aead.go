package aeadplugin

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"

	"cloud.google.com/go/pubsub"
	hclog "github.com/hashicorp/go-hclog"

	b64 "encoding/base64"
	"encoding/json"

	"github.com/Vodafone/vault-plugin-aead/aeadutils"
	"github.com/google/tink/go/tink"
	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathAeadEncrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	/*
		what is data.Raw

		is this a bulk file: ie a map of map[string]map[string]interface{} where the second map is the row to be encrypted:

		{
			"0":{"bulkfield0":"bulkfieldvalue01","bulkfield1":"bulkfieldvalue11","bulkfield2":"bulkfieldvalue21"},
			"1":{"bulkfield0":"bulkfieldvalue02","bulkfield1":"bulkfieldvalue12","bulkfield2":"bulkfieldvalue22"},
			"2":{"bulkfield0":"bulkfieldvalue03","bulkfield1":"bulkfieldvalue13","bulkfield2":"bulkfieldvalue23"}
		}

		or a single row of key value pairs to be encrypted map[string]interface{}

		{"field0":"fieldvalue0","field1":"fieldvalue1","field2":"fieldvalue2"}

	*/

	// fire and forget the telemetry
	var wg sync.WaitGroup
	wg.Add(1)
	go b.publishTelemetry(&wg, ctx, req, "encrypt", data.Raw)

	var respStruct = logical.Response{}
	var resp = &respStruct

	isBulk, _ := isBulkData(data.Raw)

	if isBulk {

		// split the bulk file into rows and process each row concurrently in a  goroutine
		channelCap := len(data.Raw)
		channel := make(chan map[string]interface{}, channelCap)

		for rowKey, rowDataMap := range data.Raw {
			rowDataMapAsMapStrInt, ok := rowDataMap.(map[string]interface{})
			if !ok {
				panic("expecting a map pathAeadEncrypt")
			}
			req.Data = rowDataMapAsMapStrInt

			// prior to this there were race conditions as multiple goroutines access data
			dn := framework.FieldData{
				Raw:    rowDataMapAsMapStrInt,
				Schema: nil,
			}

			// data.Raw = rowDataMapAsMapStrInt
			//localResp, err := b.pathAeadEncryptRowChan(ctx, req, data)
			go b.encryptRowChan(ctx, req, &dn, rowKey, channel)
		}

		resp.Data = make(map[string]interface{})
		for i := 0; i < channelCap; i++ {
			res := <-channel
			for k, v := range res {
				// this should be a map of 1 row of rownumber index as string and the map of values
				resp.Data[k] = v
			}
		}

	} else {

		// process a ringle row
		localResp, err := b.encryptRow(ctx, req, data)
		if err != nil {
			panic(err)
		}
		resp = localResp
	}
	wg.Wait()

	return resp, nil
}

func (b *backend) encryptRowChan(ctx context.Context, req *logical.Request, data *framework.FieldData, row string, ch chan map[string]interface{}) {

	// this is just a wrapper around the pathAeadEncryptRow methos so that it can be used concurrently in a channel
	resp, err := b.encryptRow(ctx, req, data)
	if err != nil {
		panic(err)
	}

	localResp := make(map[string]interface{})
	localResp[row] = resp.Data

	ch <- localResp

}

func (b *backend) decryptRowChan(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string, ch chan map[string]interface{}) {

	// this is just a wrapper around the pathAeadDecryptRow methos so that it can be used concurrently in a channel
	resp, err := b.pathAeadDecrypt(ctx, req, data)
	if err != nil {
		panic(err)
	}

	localResp := make(map[string]interface{})
	localResp[fieldName] = resp.Data

	ch <- localResp

}

func (b *backend) encryptRow(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// retrive the config fro  storage

	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	// logical.Response{
	// 	Secret:   &logical.Secret{},
	// 	Auth:     &logical.Auth{},
	// 	Data:     map[string]interface{}{},
	// 	Redirect: "",
	// 	Warnings: []string{},
	// 	WrapInfo: &wrapping.ResponseWrapInfo{},
	// 	Headers:  map[string][]string{},
	// }

	resp := make(map[string]interface{})
	channelCap := len(data.Raw)
	channel := make(chan map[string]interface{}, channelCap)

	// iterate through the key=value supplied (ie field1=myaddress field2=myphonenumber)
	for fieldName, unencryptedData := range data.Raw {
		// doEncryption(fieldName, unencryptedData, resp, data, b, ctx, req)
		go b.doEncryptionChan(fieldName, unencryptedData, data, ctx, req, channel)
	}

	for i := 0; i < channelCap; i++ {
		res := <-channel
		// this is only 1 key=value pair, but we don't know the key or the value so we iterate over a range of 1 pair
		for k, v := range res {
			resp[k] = v
		}
	}
	return &logical.Response{
		Data: resp,
	}, nil
}

func (b *backend) doEncryptionChan(fieldName string, unencryptedData interface{}, data *framework.FieldData, ctx context.Context, req *logical.Request, ch chan map[string]interface{}) {
	resp := make(map[string]interface{})
	encryptionkey, ok := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)
	// do we have a key already in config
	if ok {
		// is the key we have retrived deterministic?
		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionkey)
		// set additionalDataBytes as field name of the right type
		additionalDataBytes := b.getAdditionalData(fieldName, AEAD_CONFIG)

		if deterministic {
			// SUPPORT FOR DETERMINISTIC AEAD
			// we don't need the key handle which is returned first
			_, tinkDetAead, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("Failed to create a keyhandle", err)
			}
			// set the unencrypted data to be the right type
			unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

			// encrypt it
			cypherText, err := tinkDetAead.EncryptDeterministically(unencryptedDataBytes, additionalDataBytes)
			if err != nil {
				hclog.L().Error("Failed to encrypt", err)
			}

			// set the response as the base64 encrypted data
			resp[fieldName] = b64.StdEncoding.EncodeToString(cypherText)
		} else {
			// SUPPORT FOR NON DETERMINISTIC AEAD
			_, tinkAead, err := aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("Failed to create a keyhandle", err)
			}
			// set the unencrypted data to be the right type
			unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

			// encrypt it
			cyphertext, err := tinkAead.Encrypt(unencryptedDataBytes, additionalDataBytes)
			if err != nil {
				hclog.L().Error("Failed to encrypt", err)
			}

			// set the response as the base64 encrypted data
			resp[fieldName] = b64.StdEncoding.EncodeToString(cyphertext)
		}
	} else {
		// we didn't find a key - return original data
		// hclog.L().Info("did not find a key for field " + fieldName)
		resp[fieldName] = fmt.Sprintf("%s", unencryptedData)
	}
	ch <- resp
}

func (b *backend) pathAeadDecrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// what is data.Raw
	//
	// is this a bulk file: ie a map of map[string]map[string]interface{} where the second map is the row to be decrypted
	// {"0":{"bulkfield0":"fgbsrhbrgbr","bulkfield1":"sfgbsfbrnegnehtfngb","bulkfield2":"srbgwrgbwrgbwrg"},"1":{"bulkfield0":"srgbrgbewrgbg","bulkfield1":"egbetbgnetbn","bulkfield2":"sfbfbgwrbg"},"2":{"bulkfield0":"sfgbetbnet","bulkfield1":"sfgbetgbet","bulkfield2":"sfbegbet"}}
	//
	// or a single row of key value pairs to be encrypted map[string]interface{}
	// {"bulkfield0":"fgbsrhbrgbr","bulkfield1":"sfgbsfbrnegnehtfngb","bulkfield2":"srbgwrgbwrgbwrg"}

	// fire and forget the telemetry
	var wg sync.WaitGroup
	wg.Add(1)
	go b.publishTelemetry(&wg, ctx, req, "decrypt", data.Raw)

	var respStruct = logical.Response{}
	var resp = &respStruct

	isBulk, _ := isBulkData(data.Raw)

	if isBulk {

		channelCap := len(data.Raw)
		channel := make(chan map[string]interface{}, channelCap)

		for rowKey, rowDataMap := range data.Raw {
			rowDataMapAsMapStrInt, ok := rowDataMap.(map[string]interface{})
			if !ok {
				panic("expecting a map pathAeadEncrypt")
			}
			req.Data = rowDataMapAsMapStrInt

			// prior to this there were race conditions as multiple goroutines access data
			dn := framework.FieldData{
				Raw:    rowDataMapAsMapStrInt,
				Schema: nil,
			}

			// data.Raw = rowDataMapAsMapStrInt
			go b.decryptRowChan(ctx, req, &dn, rowKey, channel)
		}

		resp.Data = make(map[string]interface{})
		for i := 0; i < channelCap; i++ {
			res := <-channel
			for k, v := range res {
				// this should be a map of 1 row of rownumber index as string and the map of values
				resp.Data[k] = v
			}
		}

	} else {
		localResp, err := b.decryptRow(ctx, req, data)
		if err != nil {
			panic(err)
		}
		resp = localResp
	}
	wg.Wait()
	return resp, nil
}

func (b *backend) decryptRow(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}

	resp := make(map[string]interface{})
	channel := make(chan map[string]interface{}, len(data.Raw))

	// iterate through the key=value supplied (ie field1=sdfvbbvwrbwr field2=advwefvwfvbwrfvb)
	for field, encryptedDataBase64 := range data.Raw {
		// doDecryption(field, encryptedDataBase64, resp)
		go b.doDecryptionChan(field, encryptedDataBase64, channel)
	}

	for i := 0; i < len(data.Raw); i++ {
		res := <-channel
		// this is only 1 key=value pair, but we don't know the key or the value so we iterate over a range of 1 pair
		for k, v := range res {
			resp[k] = v
		}
	}

	return &logical.Response{
		Data: resp,
	}, nil
}

func (b *backend) doDecryptionChan(fieldName string, encryptedDataBase64 interface{}, ch chan map[string]interface{}) {
	resp := make(map[string]interface{})
	encryptionkey, ok := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)
	// do we have a key already in config
	if ok {
		// is the key deterministig or non deterministic
		encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionkey)

		// set additionalDataBytes as field name of the right type
		additionalDataBytes := b.getAdditionalData(fieldName, AEAD_CONFIG)

		if deterministic {
			// SUPPORT FOR DETERMINISTIC AEAD
			// we don't need the key handle which is returned first
			_, tinkDetAead, err := aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("Failed to create a  key handle", err)
			}

			// set the unencrypted data to be the right type
			encryptedDataBytes, _ := b64.StdEncoding.DecodeString(fmt.Sprintf("%v", encryptedDataBase64))

			// decrypt it
			plainText, err := tinkDetAead.DecryptDeterministically(encryptedDataBytes, additionalDataBytes)
			if err != nil {
				hclog.L().Error("Failed to decrypt ", err)
			}

			resp[fieldName] = string(plainText)
		} else {
			// SUPPORT FOR NON DETERMINISTIC AEAD
			_, tinkAead, err := aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
			if err != nil {
				hclog.L().Error("Failed to create tinkAead", err)
			}

			// set the unencrypted data to be the right type

			encryptedDataBytes, _ := b64.StdEncoding.DecodeString(fmt.Sprintf("%v", encryptedDataBase64))

			// encrypt it
			plainText, err := tinkAead.Decrypt(encryptedDataBytes, additionalDataBytes)
			if err != nil {
				hclog.L().Error("Failed to decrypt ", err)
			}

			resp[fieldName] = string(plainText)
		}
	} else {
		// we didn't find a key - return original data
		// hclog.L().Info("did not find a key for field " + fieldName)
		resp[fieldName] = fmt.Sprintf("%s", encryptedDataBase64)
	}
	ch <- resp
}

func (b *backend) pathAeadEncryptBulkCol(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	/*
		what is data.Raw

		is this a bulk file: ie a map of map[string]map[string]interface{} where the second map is the row to be encrypted:

		{
			"0":{"bulkfield0":"bulkfieldvalue01","bulkfield1":"bulkfieldvalue11","bulkfield2":"bulkfieldvalue21"},
			"1":{"bulkfield0":"bulkfieldvalue02","bulkfield1":"bulkfieldvalue12","bulkfield2":"bulkfieldvalue22"},
			"2":{"bulkfield0":"bulkfieldvalue03","bulkfield1":"bulkfieldvalue13","bulkfield2":"bulkfieldvalue23"}
		}

		or a single row of key value pairs to be encrypted map[string]interface{}

		{"field0":"fieldvalue0","field1":"fieldvalue1","field2":"fieldvalue2"}

	*/

	// fire and forget the telemetry
	var wg sync.WaitGroup
	wg.Add(1)
	go b.publishTelemetry(&wg, ctx, req, "encrypt", data.Raw)

	var respStruct = logical.Response{}
	var resp = &respStruct

	isBulk, _ := isBulkData(data.Raw)

	if isBulk {

		// ok, 1st thing to do is to pivot the map
		pivotedMap := make(map[string]interface{})
		aeadutils.PivotMapInt(data.Raw, pivotedMap)

		channelCap := len(pivotedMap)
		channel := make(chan map[string]interface{}, channelCap)

		for fieldName, rowDataMap := range pivotedMap {
			rowDataMapAsMapStrInt, ok := rowDataMap.(map[string]interface{})
			if !ok {
				panic("expecting a map pathAeadEncrypt")
			}
			req.Data = rowDataMapAsMapStrInt

			// prior to this there were race conditions as multiple goroutines access data
			dn := framework.FieldData{
				Raw:    rowDataMapAsMapStrInt,
				Schema: nil,
			}

			// data.Raw = rowDataMapAsMapStrInt
			//localResp, err := b.pathAeadEncryptRowChan(ctx, req, data)
			go b.encryptColChan(ctx, req, &dn, fieldName, channel)
		}

		resp.Data = make(map[string]interface{})
		resultsMap := make(map[string]interface{})
		for i := 0; i < channelCap; i++ {
			res := <-channel
			for k, v := range res {
				// this should be a map of 1 row of rownumber index as string and the map of values
				resultsMap[k] = v
			}
		}

		// unpivot the map
		aeadutils.PivotMapInt(resultsMap, resp.Data)

	} else {

		hclog.L().Info("can only do column ops on bulk data")

	}
	wg.Wait()

	return resp, nil
}

func (b *backend) encryptColChan(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string, ch chan map[string]interface{}) {

	// this is just a wrapper around the pathAeadEncryptRow methos so that it can be used concurrently in a channel
	resp, err := b.encryptCol(ctx, req, data, fieldName)
	if err != nil {
		panic(err)
	}

	localResp := make(map[string]interface{})
	localResp[fieldName] = resp.Data

	ch <- localResp

}

func (b *backend) encryptCol(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string) (*logical.Response, error) {

	// retrive the config fro  storage

	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	encryptionkey, keyFound := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)
	// is the key we have retrived deterministic?
	encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionkey)

	var tinkDetAead tink.DeterministicAEAD
	var tinkAead tink.AEAD

	if keyFound && deterministic {
		// SUPPORT FOR DETERMINISTIC AEAD
		// we don't need the key handle which is returned first
		_, tinkDetAead, err = aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
		if err != nil {
			hclog.L().Error("Failed to create a keyhandle", err)
			return &logical.Response{
				Data: resp,
			}, err
		}
	} else if keyFound && !deterministic {
		// SUPPORT FOR NON DETERMINISTIC AEAD
		_, tinkAead, err = aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
		if err != nil {
			hclog.L().Error("Failed to create a key", err)
			return &logical.Response{
				Data: resp,
			}, err
		}
	}
	// set additionalDataBytes as field name of the right type
	additionalDataBytes := b.getAdditionalData(fieldName, AEAD_CONFIG)

	// iterate through the key=value supplied (ie field1=myaddress field2=myphonenumber)
	for rowNum, unencryptedData := range data.Raw {
		// do we have a key already in config
		if keyFound {

			if deterministic {
				// SUPPORT FOR DETERMINISTIC AEAD

				// set the unencrypted data to be the right type
				unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

				// encrypt it
				cypherText, err := tinkDetAead.EncryptDeterministically(unencryptedDataBytes, additionalDataBytes)
				if err != nil {
					hclog.L().Error("Failed to encrypt", err)
					return &logical.Response{
						Data: resp,
					}, err
				}

				// set the response as the base64 encrypted data
				resp[rowNum] = b64.StdEncoding.EncodeToString(cypherText)
			} else {

				// set the unencrypted data to be the right type
				unencryptedDataBytes := []byte(fmt.Sprintf("%v", unencryptedData))

				// encrypt it
				cyphertext, err := tinkAead.Encrypt(unencryptedDataBytes, additionalDataBytes)
				if err != nil {
					hclog.L().Error("Failed to encrypt", err)
					return &logical.Response{
						Data: resp,
					}, err
				}

				// set the response as the base64 encrypted data
				resp[rowNum] = b64.StdEncoding.EncodeToString(cyphertext)
			}
		} else {
			// we didn't find a key - return original data
			resp[rowNum] = fmt.Sprintf("%s", unencryptedData)
		}
	}

	return &logical.Response{
		Data: resp,
	}, nil
}

func (b *backend) pathAeadDecryptBulkCol(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// what is data.Raw
	//
	// is this a bulk file: ie a map of map[string]map[string]interface{} where the second map is the row to be decrypted
	// {"0":{"bulkfield0":"fgbsrhbrgbr","bulkfield1":"sfgbsfbrnegnehtfngb","bulkfield2":"srbgwrgbwrgbwrg"},"1":{"bulkfield0":"srgbrgbewrgbg","bulkfield1":"egbetbgnetbn","bulkfield2":"sfbfbgwrbg"},"2":{"bulkfield0":"sfgbetbnet","bulkfield1":"sfgbetgbet","bulkfield2":"sfbegbet"}}
	//
	// or a single row of key value pairs to be encrypted map[string]interface{}
	// {"bulkfield0":"fgbsrhbrgbr","bulkfield1":"sfgbsfbrnegnehtfngb","bulkfield2":"srbgwrgbwrgbwrg"}

	// fire and forget the telemetry
	var wg sync.WaitGroup
	wg.Add(1)
	go b.publishTelemetry(&wg, ctx, req, "decrypt", data.Raw)

	var respStruct = logical.Response{}
	var resp = &respStruct

	isBulk, _ := isBulkData(data.Raw)

	if isBulk {

		// ok, 1st thing to do is to pivot the map
		pivotedMap := make(map[string]interface{})
		aeadutils.PivotMapInt(data.Raw, pivotedMap)

		channelCap := len(pivotedMap)
		channel := make(chan map[string]interface{}, channelCap)

		for fieldName, rowDataMap := range pivotedMap {
			rowDataMapAsMapStrInt, ok := rowDataMap.(map[string]interface{})
			if !ok {
				hclog.L().Error("expecting a map")
				return &logical.Response{
					Data: make(map[string]interface{}),
				}, nil
			}
			req.Data = rowDataMapAsMapStrInt

			// prior to this there were race conditions as multiple goroutines access data
			dn := framework.FieldData{
				Raw:    rowDataMapAsMapStrInt,
				Schema: nil,
			}

			// data.Raw = rowDataMapAsMapStrInt
			go b.decryptColChan(ctx, req, &dn, fieldName, channel)
		}

		resp.Data = make(map[string]interface{})
		resultsMap := make(map[string]interface{})

		for i := 0; i < channelCap; i++ {
			res := <-channel
			for k, v := range res {
				// this should be a map of 1 row of rownumber index as string and the map of values
				resultsMap[k] = v
			}
		}

		// unpivot the map
		aeadutils.PivotMapInt(resultsMap, resp.Data)

	} else {
		hclog.L().Info("can only do column ops on bulk data")
	}
	wg.Wait()

	return resp, nil
}

func (b *backend) decryptColChan(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string, ch chan map[string]interface{}) {

	// this is just a wrapper around the pathAeadDecryptRow methos so that it can be used concurrently in a channel
	resp, err := b.decryptCol(ctx, req, data, fieldName)
	if err != nil {
		panic(err)
	}

	localResp := make(map[string]interface{})
	localResp[fieldName] = resp.Data

	ch <- localResp

}

func (b *backend) decryptCol(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string) (*logical.Response, error) {
	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]interface{})

	encryptionkey, keyFound := aeadutils.GetEncryptionKey(fieldName, AEAD_CONFIG)
	// is the key we have retrived deterministic?
	encryptionKeyStr, deterministic := aeadutils.IsKeyJsonDeterministic(encryptionkey)

	var tinkDetAead tink.DeterministicAEAD
	var tinkAead tink.AEAD

	if keyFound && deterministic {
		// SUPPORT FOR DETERMINISTIC AEAD
		// we don't need the key handle which is returned first
		_, tinkDetAead, err = aeadutils.CreateInsecureHandleAndDeterministicAead(encryptionKeyStr)
		if err != nil {
			hclog.L().Error("Failed to create a key handle", err)
			return &logical.Response{
				Data: resp,
			}, err
		}
	} else if keyFound && !deterministic {
		// SUPPORT FOR NON DETERMINISTIC AEAD
		_, tinkAead, err = aeadutils.CreateInsecureHandleAndAead(encryptionKeyStr)
		if err != nil {
			hclog.L().Error("Failed to create a key handle", err)
			return &logical.Response{
				Data: resp,
			}, err
		}
	}
	// set additionalDataBytes as field name of the right type
	additionalDataBytes := b.getAdditionalData(fieldName, AEAD_CONFIG)

	// iterate through the key=value supplied (ie field1=sdfvbbvwrbwr field2=advwefvwfvbwrfvb)
	for rowNumber, encryptedDataBase64 := range data.Raw {
		if keyFound {
			if deterministic {

				// SUPPORT FOR DETERMINISTIC AEAD
				// set the unencrypted data to be the right type
				encryptedDataBytes, _ := b64.StdEncoding.DecodeString(fmt.Sprintf("%v", encryptedDataBase64))

				// decrypt it
				plainText, err := tinkDetAead.DecryptDeterministically(encryptedDataBytes, additionalDataBytes)
				if err != nil {
					hclog.L().Error("Failed to decrypt", err)
					return &logical.Response{
						Data: resp,
					}, err
				}

				resp[rowNumber] = string(plainText)
			} else {
				// SUPPORT FOR NON DETERMINISTIC AEAD
				// set the unencrypted data to be the right type

				encryptedDataBytes, _ := b64.StdEncoding.DecodeString(fmt.Sprintf("%v", encryptedDataBase64))

				// encrypt it
				plainText, err := tinkAead.Decrypt(encryptedDataBytes, additionalDataBytes)
				if err != nil {
					hclog.L().Error("Failed to decrypt", err)
					return &logical.Response{
						Data: resp,
					}, err
				}

				resp[rowNumber] = string(plainText)
			}
		} else {
			// we didn't find a key - return original data
			// hclog.L().Info("did not find a key for field " + fieldName)
			resp[rowNumber] = fmt.Sprintf("%s", encryptedDataBase64)
		}
	}

	return &logical.Response{
		Data: resp,
	}, nil
}

func isBulkData(data map[string]interface{}) (bool, error) {
	// it is bulk data if it is a nested map
	// map[string]map[string]interface{}
	// else it is not bulk data because it is
	// map[string]interface{}
	for _, v := range data {
		// is the value of the outer map another mnap
		_, ok := v.(map[string]interface{})
		return ok, nil
	}
	// this should never be reached
	return false, nil
}

func (b *backend) publishTelemetry(wg *sync.WaitGroup, ctx context.Context, req *logical.Request, encryptOrDecrypt string, data map[string]interface{}) {

	defer wg.Done()

	// retrive the config from  storage
	err := b.getAeadConfig(ctx, req)
	if err != nil {
		return
	}

	var market string
	telemetryLMIntf, ok := AEAD_CONFIG.Get("TELEMETRY_LM")
	if !ok {
		return
		//market = "test"
	} else {
		market = fmt.Sprintf("%s", telemetryLMIntf)
	}

	// it is bulk data if it is a nested map
	// map[string]map[string]interface{}
	// else it is not bulk data because it is
	// map[string]interface{}

	rows := len(data)
	fields := 1

	for _, v := range data {
		// is the value of the outer map another mnap
		mi, ok := v.(map[string]interface{})
		if ok {
			fields = len(mi)
		}
	}

	// Sets your Google Cloud Platform project ID.
	var projectID string
	telemetryProjectIDIntf, ok := AEAD_CONFIG.Get("TELEMETRY_PROJECTID")
	if !ok {
		projectID = "your-pubsub-project"
	} else {
		projectID = fmt.Sprintf("%s", telemetryProjectIDIntf)
	}

	// Sets the id for the new topic.
	var topicID string
	telemetryTopicIDIntf, ok := AEAD_CONFIG.Get("TELEMETRY_TOPICID")
	if !ok {
		topicID = "eaas-telemetry"
	} else {
		topicID = fmt.Sprintf("%s", telemetryTopicIDIntf)
	}

	// Creates a client.
	client, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		hclog.L().Error("Failed to create client: %v", err)
	}
	defer client.Close()

	// Creates the new topic.

	type Message struct {
		Uuid             string `json:"uuid"`
		Market           string `json:"market"`
		PubDate          string `json:"pubDate"`
		EncryptOrDecrypt string `json:"encryptOrDecrypt"`
		ReqSize          int    `json:"reqSize"`
		ReqRows          int    `json:"reqRows"`
		ReqFields        int    `json:"reqFields"`
	}

	tn := time.Now().UTC().String()
	newUuid := uuid.New()
	sz := unsafe.Sizeof(data)

	msg := Message{newUuid.String(), market, tn, encryptOrDecrypt, int(sz), rows, fields}
	payload, err := json.Marshal(msg)

	if err != nil {
		log.Fatalf("pubsub: json.Marshal: %v", err)
	}

	t := client.Topic(topicID)
	result := t.Publish(ctx, &pubsub.Message{
		Data: payload,
	})

	// Block until the result is returned and a server-generated
	// ID is returned for the published message.
	_, err = result.Get(ctx)
	if err != nil {
		hclog.L().Error("pubsub: result.Get: %v", err)
	}
}
