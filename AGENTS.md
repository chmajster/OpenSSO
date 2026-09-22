## Zasady pracy nad repozytorium

Przed rozpoczęciem zmian dokładnie przeanalizuj całe repozytorium projektu.

Nie ograniczaj analizy wyłącznie do plików wskazanych w zadaniu. Sprawdź również powiązane moduły, zależności, API, modele danych, UI oraz istniejące testy.

## Git i Pull Request

Każde zadanie wykonuj na osobnym branchu.

Nie wykonuj zmian bezpośrednio na `main`.

Na początku pracy:

1. Utwórz osobny branch roboczy.
2. Jak najszybciej utwórz Draft Pull Request do `main`.
3. Nie czekaj z utworzeniem PR do zakończenia implementacji.

Draft PR ma służyć również jako zapis aktualnego stanu pracy na wypadek przerwania sesji.

Opis PR musi zawierać:

```text
## Goal
Cel zadania.

## Scope
Zakres wykonywanych zmian.

## Findings
Problemy znalezione podczas analizy.

## Completed
Elementy już ukończone.

## Remaining work
Elementy, które nadal wymagają wykonania.

## Known issues
Znane problemy lub blokery.

## Tests
Wykonane testy i ich wyniki.

## Verification
Wynik weryfikacji end-to-end.
```

Aktualizuj opis PR podczas pracy, szczególnie po większych etapach.

Jeżeli praca zostanie przerwana, `Remaining work` musi pozwolić kolejnej sesji dokładnie ustalić, gdzie kontynuować.

## Analiza projektu

Podczas pracy analizuj projekt pod kątem:

- architektury,
- separacji odpowiedzialności,
- jakości kodu,
- czytelności kodu,
- duplikacji,
- martwego kodu,
- zależności pomiędzy modułami,
- obsługi wyjątków,
- obsługi błędów,
- walidacji danych,
- bezpieczeństwa,
- uwierzytelniania,
- autoryzacji,
- RBAC,
- przechowywania sekretów,
- kontroli dostępu,
- API,
- modeli danych,
- migracji,
- bazy danych,
- wydajności,
- zapytań do bazy,
- cache,
- kolejek,
- workerów,
- operacji asynchronicznych,
- idempotencji,
- race conditions,
- blokad,
- logowania,
- audytu,
- konfiguracji,
- instalacji,
- aktualizacji,
- CI/CD,
- testów,
- UI,
- UX,
- responsywności,
- dostępności,
- spójności interfejsu,
- integracji frontend-backend.

Nie ograniczaj się do opisania problemów.

Jeżeli znaleziony problem jest bezpośrednio związany z wykonywanym zadaniem, popraw go.

## Implementacja

Nie implementuj wyłącznie minimalnej wersji funkcji.

Doprowadź funkcjonalność do kompletnego, działającego stanu.

Nie pozostawiaj:

- `TODO`,
- `FIXME`,
- placeholderów,
- atrap,
- mocków zastępujących właściwą implementację,
- tymczasowych endpointów,
- przykładowych danych produkcyjnych,
- pustych ekranów,
- niedziałających przycisków,
- elementów UI bez implementacji backendowej,
- endpointów zwracających dane tymczasowe,
- funkcji udających działające.

Jeżeli funkcja jest widoczna dla użytkownika, musi działać.

Jeżeli nie można jej poprawnie ukończyć, nie pozostawiaj niedziałającego elementu w UI.

Nie kończ implementacji tylko dlatego, że podstawowy scenariusz działa.

## Sprawdzanie istniejącego kodu

Przy okazji zmiany sprawdź kod bezpośrednio związany z modyfikowanym obszarem.

Szukaj między innymi:

- nieobsłużonych błędów,
- nieprawidłowych statusów,
- niespójności modeli,
- błędów API,
- problemów z synchronizacją stanu,
- błędnej walidacji,
- złej obsługi `null`,
- błędów przy ponownym wykonaniu,
- problemów po odświeżeniu strony,
- problemów po restarcie aplikacji,
- regresji,
- problemów bezpieczeństwa.

Nie wykonuj niepotrzebnych dużych refaktorów niezwiązanych z zadaniem.

## Commity

Twórz logiczne i możliwie małe commity.

Każdy commit powinien reprezentować konkretną część implementacji.

Nie wrzucaj całego dużego zadania jako jednego nieczytelnego commita, jeśli można je logicznie podzielić.

Nie commituj:

- sekretów,
- haseł,
- tokenów,
- plików tymczasowych,
- logów,
- build artifacts,
- danych debugowych.

## Testy

Po zmianach uruchom wszystkie testy mające zastosowanie do zmodyfikowanego obszaru.

W zależności od projektu sprawdź:

- testy jednostkowe,
- testy integracyjne,
- testy API,
- testy frontendowe,
- testy end-to-end,
- lint,
- type-checking,
- build,
- migracje,
- instalator,
- aktualizację aplikacji.

Jeżeli zmieniana jest krytyczna logika i nie ma dla niej testów, dodaj odpowiednie testy.

Nie traktuj samego przejścia testów jako wystarczającego potwierdzenia poprawności.

## Weryfikacja end-to-end

Po implementacji sprawdź cały przepływ funkcji.

Dla typowej funkcjonalności:

```text
UI
→ API
→ backend
→ baza danych / provider / worker
→ wykonanie operacji
→ aktualizacja stanu
→ API
→ ponowne wyświetlenie poprawnego stanu w UI
```

Sprawdź nie tylko happy path.

Zweryfikuj także, jeśli mają zastosowanie:

- błędne dane wejściowe,
- brak danych,
- brak uprawnień,
- wygaśniętą sesję,
- niedostępność backendu,
- niedostępność zewnętrznego providera,
- timeout,
- częściowe niepowodzenie,
- ponowienie operacji,
- podwójne kliknięcie,
- równoległe operacje,
- odświeżenie strony,
- restart workera,
- restart aplikacji,
- anulowanie operacji,
- retry,
- błędy sieciowe.

## UI/UX

Każdy dodany element UI musi być funkcjonalny.

Sprawdź:

- widok desktopowy,
- mniejszą rozdzielczość,
- responsywność,
- loading state,
- empty state,
- error state,
- disabled state,
- feedback po wykonaniu akcji.

Przycisk nie może istnieć tylko wizualnie.

Akcja użytkownika musi mieć widoczny wynik albo komunikat błędu.

Nie ukrywaj błędów backendu pod ogólnym komunikatem, jeżeli można bezpiecznie wyświetlić użytkownikowi bardziej użyteczną informację.

## Bezpieczeństwo

Przy każdej zmianie sprawdź:

- autoryzację endpointów,
- kontrolę dostępu do zasobów,
- RBAC,
- walidację wejścia,
- możliwość IDOR,
- SQL injection,
- command injection,
- path traversal,
- XSS,
- CSRF,
- SSRF,
- niebezpieczne deserializacje,
- ujawnianie sekretów,
- logowanie danych wrażliwych,
- błędne uprawnienia administracyjne.

Frontend nie jest mechanizmem bezpieczeństwa.

Każde ograniczenie dostępu musi być egzekwowane również po stronie backendu.

## Wydajność

Sprawdź, czy zmiany nie powodują:

- N+1 queries,
- niepotrzebnych zapytań,
- niepotrzebnych requestów,
- nieskończonego pollingu,
- blokowania requestów przez długie operacje,
- ładowania nadmiarowych danych,
- zbędnego renderowania UI,
- nadmiernego użycia pamięci,
- nieograniczonych pętli,
- niekontrolowanego tworzenia jobów.

Długotrwałe operacje powinny być wykonywane zgodnie z istniejącą architekturą projektu, np. poprzez joby/workery.

## Przed zakończeniem zadania

Wykonaj finalny przegląd zmian.

Sprawdź:

```bash
git status
git diff
git diff main...HEAD
```

Zweryfikuj, czy:

- nie ma przypadkowych zmian,
- nie ma debugowego kodu,
- nie ma sekretów,
- nie ma nowych TODO,
- nie ma placeholderów,
- nie ma martwego kodu,
- nie ma niedziałających przycisków,
- nie ma niedokończonych endpointów,
- nie ma brakujących migracji,
- testy przechodzą,
- build przechodzi,
- zmieniona funkcjonalność działa end-to-end.

Wykonaj również ponowny code review własnych zmian.

## Kryteria ukończenia

Zadanie można uznać za zakończone tylko wtedy, gdy:

- implementacja jest kompletna,
- funkcjonalność działa end-to-end,
- backend działa poprawnie,
- UI działa poprawnie,
- obsługa błędów działa,
- walidacja działa,
- wymagane testy przechodzą,
- build przechodzi,
- migracje działają,
- nie ma znanych blockerów,
- nie ma elementów niedokończonych w zakresie zadania,
- nie pozostawiono placeholderów ani TODO,
- opis PR odpowiada rzeczywistemu stanowi projektu.

## Merge

Jeżeli PR jest kompletny i nie ma znanych problemów blokujących:

1. Zaktualizuj opis PR.
2. Upewnij się, że `Remaining work` jest puste.
3. Upewnij się, że `Known issues` nie zawiera problemów blokujących.
4. Wykonaj finalny review.
5. Upewnij się, że testy i build przechodzą.
6. Zmerguj PR do `main`.
7. Sprawdź, czy zmiany rzeczywiście znajdują się w `main`.
8. Usuń branch roboczy po poprawnym merge.

Nie merguj zmian, jeżeli:

- implementacja jest niekompletna,
- testy nie przechodzą,
- build nie przechodzi,
- istnieje znany blocker,
- istnieje ryzyko utraty danych,
- migracja nie została zweryfikowana,
- podstawowy przepływ end-to-end nie działa.

## Najważniejsza zasada

Nie kończ pracy po wykonaniu pierwszej działającej wersji.

Po implementacji ponownie przeanalizuj cały zmieniony obszar, wykonaj testy end-to-end i usuń znalezione problemy związane z wykonywanym zadaniem.

Celem jest dostarczenie kompletnej, zweryfikowanej i gotowej do użycia zmiany, a nie jedynie kodu spełniającego podstawowy scenariusz.
