   # Clawback Protocol                                                                                                  
                                                                                                                        
   **Your data was never theirs to keep.**                                                                              
                                                                                                                        
   Clawback is an open protocol for **revocable, time-limited, and verifiable data sharing**. It gives people           
 cryptographically enforced control over their personal data — not through terms of service, but through math.          
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## The Problem                                                                                                       
                                                                                                                        
   When you share personal data with a service, you lose control of it. Forever. They can store it, sell it, lose it in 
  a breach, or quietly ignore their own deletion policies. Legal agreements are unenforceable in practice. Your data    
 becomes their asset.                                                                                                   
                                                                                                                        
   ## The Solution                                                                                                      
                                                                                                                        
   Clawback replaces **data transfer** with **scoped access**. Your data never leaves your control. Services receive    
 time-limited, scope-restricted credentials that cryptographically expire. When the window closes, access is revoked —  
 and destruction is provable.                                                                                           
                                                                                                                        
   No trust required. No terms of service. Just cryptography.                                                           
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## How It Works                                                                                                      
                                                                                                                        
   You ──► Issue a Clawback Credential (scoped, time-limited)                                                           
                 │                                                                                                      
          Service receives temporary access                                                                             
                 │                                                                                                      
          Access window expires                                                                                         
                 │                                                                                                      
          Credential self-revokes ──► Provable destruction                                                              
                                                                                                                        
   **Three core capabilities:**                                                                                         
                                                                                                                        
  **Scoped Sharing** — Share only what's needed, for only as long as needed. A shipping address for 24 hours. An ID 
  for 60 seconds. You decide.                                                                                           
                                                                                                                        
  **Zero-Knowledge Verification** — Prove facts without revealing data. "Yes, I'm over 18" without showing your ID. 
  "Yes, I live in this state" without giving your address.                                                              
                                                                                                                        
  **Provable Destruction** — Cryptographic proof that your data has been deleted. Not "trust us" — mathematically   
 verifiable.                                                                                                            
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## Who It's For                                                                                                      
                                                                                                                        
   Clawback is **infrastructure**, not an app. It's designed for integration into existing platforms:                   
                                                                                                                        
   - **Messaging apps** — Share documents that provably self-destruct                                                   
   - **Email providers** — Attachments with enforced expiration                                                         
   - **Password managers** — Temporary credential sharing                                                               
   - **Identity verification** — KYC without data hoarding                                                              
   - **E-commerce** — Transactions without permanent data retention                                                     
                                                                                                                        
   If your platform handles personal data, Clawback makes your users safer.                                             
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## Project Status                                                                                                    
                                                                                                                        
   **Early Development**                                                                                             
                                                                                                                        
   - [x] Protocol concept defined                                                                                       
   - [x] Specification v0.1 drafted                                                                                     
   - [ ] Reference SDK (Rust)                                                                                           
   - [ ] Reference SDK (TypeScript)                                                                                     
   - [x] Proof of concept demo — see [`poc` branch](https://github.com/clawback-protocol/spec/tree/poc)                                                                                          
   - [ ] Security audit                                                                                                 
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## Protocol Specification                                                                                            
                                                                                                                        
   See spec/SPEC-v0.1.md for the full protocol specification, including:                                                
                                                                                                                        
   - Architecture overview                                                                                              
   - Core data-sharing flows                                                                                            
   - Credential schema                                                                                                  
   - Cryptographic mechanisms                                                                                           
   - SDK interface reference                                                                                            
   - Compliance mapping (GDPR, CCPA)                                                                                    
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## Technical Foundation                                                                                              
                                                                                                                        
   - **AES-256-GCM** — Payload encryption                                                                               
   - **Argon2id** — Key derivation                                                                                      
   - **X25519** — Key exchange                                                                                          
   - **Bulletproofs / zk-SNARKs** — Zero-knowledge proofs                                                               
   - **Time-lock cryptography** — Enforced expiration                                                                   
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## Get Involved                                                                                                      
                                                                                                                        
   This project is in its early stages. If you believe people deserve real control over their data, we'd love your      
 help.                                                                                                                  
                                                                                                                        
   - 📖 Read the spec                                                                                                   
   - 💬 Open an issue to discuss ideas                                                                                  
   - 🔧 Check CONTRIBUTING.md for how to contribute                                                                     
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   ## License                                                                                                           
                                                                                                                        
   This project is licensed under the GNU Affero General Public License v3.0 — ensuring it stays open, forever.         
                                                                                                                        
   ---                                                                                                                  
                                                                                                                        
   *Clawback Protocol is an independent open source project. Not affiliated with any corporation.*  
