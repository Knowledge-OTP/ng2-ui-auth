import { ConfigService } from './config.service';
export declare abstract class StorageService {
    abstract get(key: string): string;
    abstract set(key: string, value: string, date: string): void;
    abstract remove(key: string): void;
}
/**
 * Created by Ron on 17/12/2015.
 */
export declare class BrowserStorageService extends StorageService {
    private config;
    private store;
    private isStorageAvailable;
    constructor(config: ConfigService);
    get(key: string): any;
    set(key: string, value: string, date: string): void;
    remove(key: string): void;
    private checkIsStorageAvailable(config);
    private isCookieStorageAvailable();
    private setCookie(key, value, expires?, path?);
    private removeCookie(key, path?);
    private getCookie(key);
}
