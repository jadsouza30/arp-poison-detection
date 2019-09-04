#include <mac_hash.h>

bool mac_hash::search(struct macip *searchval){
    bool returnval=false;
    macip* startval=known_hosts[(int)searchval->ip[3]];
    while(startval!=NULL){
        if(is_same_ip(*startval,*searchval)){
            if(is_same_mac(startval,searchval)){
                return true;
            }
        }
        startval=startval->next;
    }
    return returnval;
}
bool mac_hash::is_same_ip(struct macip* one, struct macip* two){
    if(strncmp(one->ip,two->ip,4)!=0){
        return false;
    }
    else{
        return true;
    }
}

bool mac_hash::is_same_mac(struct macip* one, struct macip* two){
    if(strncmp(one->mac,two->mac,6)!=0){
        return false;
    }
    else{
        return true;
    }
}

void mac_hash::add(struct macip* addval){
    macip* startval=known_hosts[(int)addval->ip[3]];
    while(startval->next!=NULL){
        startval=startval->next;
    }
    startval->next=addval;
    addval->next=NULL;
}