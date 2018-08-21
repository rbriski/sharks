package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// ClientID for Auth0
const ClientID = "RpIMZwjG6BQ9uR6I6IUOPLt4kdmN68Ck"

// Domain for Sharks SBYS Auth0
const Domain = "sharkssbys.auth0.com"

var store = sessions.NewCookieStore([]byte(os.Getenv("SHARKS_COOKIE_ID")))

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/callback", CallbackHandler)
	r.HandleFunc("/login", LoginHandler)

	log.Fatal(http.ListenAndServe(":3000", r))
}

// CallbackHandler handles the Auth0 callback
func CallbackHandler(w http.ResponseWriter, r *http.Request) {

	conf := &oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: os.Getenv("AUTH0_SECRET"),
		RedirectURL:  "http://localhost:3000/callback",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + Domain + "/authorize",
			TokenURL: "https://" + Domain + "/oauth/token",
		},
	}
	state := r.URL.Query().Get("state")
	session, err := store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if state != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := conf.Exchange(context.TODO(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Getting now the userInfo
	client := conf.Client(context.TODO(), token)
	resp, err := client.Get("https://" + Domain + "/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var profile map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err = store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = token.Extra("id_token")
	session.Values["access_token"] = token.AccessToken
	session.Values["profile"] = profile
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to logged in page
	http.Redirect(w, r, "/user", http.StatusSeeOther)

}

//LoginHandler logs users in using Auth0
func LoginHandler(w http.ResponseWriter, r *http.Request) {

	conf := &oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: os.Getenv("AUTH0_SECRET"),
		RedirectURL:  "http://localhost:3000/callback",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + Domain + "/authorize",
			TokenURL: "https://" + Domain + "/oauth/token",
		},
	}

	aud := "https://" + Domain + "/userinfo"

	// Generate random state
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, err := store.Get(r, "state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audience := oauth2.SetAuthURLParam("audience", aud)
	url := conf.AuthCodeURL(state, audience)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
