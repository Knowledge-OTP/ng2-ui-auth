import { Observable } from 'rxjs/Observable';
import { ConfigService, IPopupOptions } from './config.service';
import 'rxjs/add/observable/interval';
import 'rxjs/add/observable/fromEvent';
import 'rxjs/add/observable/throw';
import 'rxjs/add/observable/empty';
import 'rxjs/add/observable/merge';
import 'rxjs/add/operator/switchMap';
import 'rxjs/add/operator/take';
import 'rxjs/add/operator/map';
import 'rxjs/add/operator/takeWhile';
import 'rxjs/add/operator/delay';
/**
 * Created by Ron on 17/12/2015.
 */
export declare class PopupService {
    private config;
    url: string;
    popupWindow: Window;
    constructor(config: ConfigService);
    open(url: string, name: string, options: IPopupOptions): this;
    eventListener(redirectUri: string): Observable<any>;
    pollPopup(): Observable<any>;
    private prepareOptions(options);
    private stringifyOptions(options);
    private parseQueryString(joinedKeyValue);
}
